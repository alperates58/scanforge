<?php

namespace App\Services;

use App\Models\AssetDiscovery;
use App\Models\CookieObservation;
use App\Models\HttpObservation;
use App\Models\RedirectObservation;
use App\Models\SecurityHeaderObservation;
use App\Models\Website;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Validation\ValidationException;

class HttpObservationService
{
    private const SECURITY_HEADERS = [
        'hsts' => 'strict-transport-security',
        'csp' => 'content-security-policy',
        'x_frame_options' => 'x-frame-options',
        'x_content_type_options' => 'x-content-type-options',
        'permissions_policy' => 'permissions-policy',
        'referrer_policy' => 'referrer-policy',
        'cross_origin_embedder_policy' => 'cross-origin-embedder-policy',
        'cross_origin_opener_policy' => 'cross-origin-opener-policy',
        'cross_origin_resource_policy' => 'cross-origin-resource-policy',
    ];

    public function __construct(private readonly TargetUrlGuard $targetUrlGuard)
    {
    }

    /**
     * @return array<string, mixed>
     */
    public function discover(Website $website, AssetDiscovery $discovery): array
    {
        $started = microtime(true);
        $url = $this->origin($website).'/';
        $fetch = $this->fetchWithRedirects($website, $url);
        $now = Carbon::now();

        $response = $fetch['response'];
        $headers = $response?->headers() ?? [];
        $body = $response?->body() ?? '';
        $body = $this->trimBody($body);
        $bodyHash = $body === '' ? null : hash('sha256', $body);
        $html = $this->parseHtmlSignals($body);
        $cookies = $this->parseCookies($headers, (string) parse_url($fetch['final_url'] ?? $url, PHP_URL_HOST));
        $faviconHash = $this->fetchFaviconHash($website, $fetch['final_url'] ?? $url);
        $robots = $this->fetchTextAsset($website, '/robots.txt');
        $sitemap = $this->fetchTextAsset($website, '/sitemap.xml');

        $observation = HttpObservation::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'asset_discovery_id' => $discovery->id,
            'url' => $url,
            'final_url' => $fetch['final_url'],
            'status_code' => $response?->status(),
            'title' => $html['title'],
            'server_header' => $this->headerValue($headers, 'server'),
            'powered_by_header' => $this->headerValue($headers, 'x-powered-by'),
            'headers' => $this->flattenHeaders($headers),
            'response_headers_raw' => $headers,
            'cookies' => $cookies,
            'redirect_chain' => $fetch['redirects'],
            'response_time_ms' => (int) round((microtime(true) - $started) * 1000),
            'body_sha256' => $bodyHash,
            'body_hash_sha256' => $bodyHash,
            'favicon_hash' => $faviconHash,
            'html_lang' => $html['lang'],
            'html_doctype' => $html['doctype'],
            'html_size_bytes' => strlen($body),
            'body_title' => $html['title'],
            'body_description' => $html['description'],
            'generator_meta' => $html['generator'],
            'observed_at' => $now,
        ]);

        foreach ($fetch['redirects'] as $redirect) {
            RedirectObservation::query()->create([
                'workspace_id' => $website->workspace_id,
                'website_id' => $website->id,
                'asset_discovery_id' => $discovery->id,
                'http_observation_id' => $observation->id,
                'order' => $redirect['order'],
                'from_url' => $redirect['from_url'],
                'to_url' => $redirect['to_url'],
                'status_code' => $redirect['status_code'],
                'observed_at' => $now,
            ]);
        }

        $securityHeaders = $this->securityHeaderMatrix($headers);

        foreach ($securityHeaders as $key => $state) {
            SecurityHeaderObservation::query()->create([
                'workspace_id' => $website->workspace_id,
                'website_id' => $website->id,
                'asset_discovery_id' => $discovery->id,
                'http_observation_id' => $observation->id,
                'header_key' => $key,
                'present' => $state['present'],
                'value' => $state['value'],
                'recommendation' => $state['recommendation'],
                'observed_at' => $now,
            ]);
        }

        foreach ($cookies as $cookie) {
            CookieObservation::query()->create([
                'workspace_id' => $website->workspace_id,
                'website_id' => $website->id,
                'asset_discovery_id' => $discovery->id,
                'http_observation_id' => $observation->id,
                'name' => $cookie['name'],
                'domain' => $cookie['domain'],
                'path' => $cookie['path'],
                'secure' => $cookie['secure'],
                'http_only' => $cookie['http_only'],
                'same_site' => $cookie['same_site'],
                'expires_at' => $cookie['expires_at'],
                'persistent' => $cookie['persistent'],
                'host_only' => $cookie['host_only'],
                'observed_at' => $now,
            ]);
        }

        return [
            'observation' => $observation->fresh(['securityHeaders', 'cookieObservations', 'redirects']),
            'security_headers' => $securityHeaders,
            'cookies' => $cookies,
            'redirects' => $fetch['redirects'],
            'robots' => $robots,
            'sitemap' => $sitemap,
            'error' => $fetch['error'],
            'total_headers' => count($this->flattenHeaders($headers)),
            'total_cookies' => count($cookies),
            'body_sample' => $body,
        ];
    }

    /**
     * @return array{response: Response|null, final_url: string, redirects: list<array{order: int, from_url: string, to_url: string, status_code: int}>, error: string|null}
     */
    private function fetchWithRedirects(Website $website, string $url): array
    {
        $redirects = [];
        $maxRedirects = (int) config('scanforge.discovery.max_redirects', 5);
        $timeout = (int) config('scanforge.discovery.timeout_seconds', 5);
        $currentUrl = $url;

        for ($i = 0; $i < $maxRedirects; $i++) {
            $response = Http::timeout($timeout)
                ->withoutRedirecting()
                ->accept('text/html,application/xhtml+xml,text/plain,*/*')
                ->get($currentUrl);

            if (! $this->isRedirectResponse($response)) {
                return [
                    'response' => $response,
                    'final_url' => $currentUrl,
                    'redirects' => $redirects,
                    'error' => null,
                ];
            }

            $location = $response->header('Location');

            if (! is_string($location) || $location === '') {
                return [
                    'response' => $response,
                    'final_url' => $currentUrl,
                    'redirects' => $redirects,
                    'error' => 'redirect_without_location',
                ];
            }

            $nextUrl = $this->resolveRedirect($currentUrl, $location);
            $nextHost = strtolower((string) parse_url($nextUrl, PHP_URL_HOST));

            if (! $this->isAllowedRedirectHost($website, $nextHost)) {
                return [
                    'response' => $response,
                    'final_url' => $currentUrl,
                    'redirects' => $redirects,
                    'error' => 'redirect_left_verified_root_domain',
                ];
            }

            try {
                $this->targetUrlGuard->assertPublicHost($nextHost);
            } catch (ValidationException) {
                return [
                    'response' => $response,
                    'final_url' => $currentUrl,
                    'redirects' => $redirects,
                    'error' => 'redirect_target_not_public',
                ];
            }

            $redirects[] = [
                'order' => count($redirects) + 1,
                'from_url' => $currentUrl,
                'to_url' => $nextUrl,
                'status_code' => $response->status(),
            ];

            $currentUrl = $nextUrl;
        }

        return [
            'response' => null,
            'final_url' => $currentUrl,
            'redirects' => $redirects,
            'error' => 'redirect_limit_exceeded',
        ];
    }

    private function isRedirectResponse(Response $response): bool
    {
        return in_array($response->status(), [301, 302, 303, 307, 308], true);
    }

    private function fetchFaviconHash(Website $website, string $finalUrl): ?string
    {
        $url = $this->urlForPath($finalUrl, '/favicon.ico');
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));

        if (! $this->isAllowedRedirectHost($website, $host)) {
            return null;
        }

        $response = Http::timeout((int) config('scanforge.discovery.timeout_seconds', 5))
            ->withoutRedirecting()
            ->get($url);

        if (! $response->successful() || $response->body() === '') {
            return null;
        }

        return hash('sha256', $response->body());
    }

    /**
     * @return array{available: bool, status_code: int|null, sensitive_paths: list<string>}
     */
    private function fetchTextAsset(Website $website, string $path): array
    {
        $url = $this->origin($website).$path;
        $response = Http::timeout((int) config('scanforge.discovery.timeout_seconds', 5))
            ->withoutRedirecting()
            ->accept('text/plain,application/xml,text/xml,*/*')
            ->get($url);

        $body = $this->trimBody($response->body());

        return [
            'available' => $response->successful(),
            'status_code' => $response->status(),
            'sensitive_paths' => $path === '/robots.txt' ? $this->sensitiveRobotsPaths($body) : [],
        ];
    }

    /**
     * @return array<string, array{present: bool, value: string|null, recommendation: string}>
     */
    private function securityHeaderMatrix(array $headers): array
    {
        $matrix = [];

        foreach (self::SECURITY_HEADERS as $key => $headerName) {
            $value = $this->headerValue($headers, $headerName);
            $matrix[$key] = [
                'present' => $value !== null && $value !== '',
                'value' => $value,
                'recommendation' => $value ? 'Review policy strength and keep it intentionally scoped.' : $this->recommendation($key),
            ];
        }

        return $matrix;
    }

    private function recommendation(string $key): string
    {
        return match ($key) {
            'hsts' => 'Add Strict-Transport-Security after confirming HTTPS is enforced for the full host.',
            'csp' => 'Add a Content-Security-Policy that matches the application asset model.',
            'x_frame_options' => 'Add X-Frame-Options or an equivalent CSP frame-ancestors directive.',
            'x_content_type_options' => 'Add X-Content-Type-Options: nosniff.',
            'permissions_policy' => 'Add Permissions-Policy to restrict browser features.',
            'referrer_policy' => 'Add Referrer-Policy to reduce cross-site URL leakage.',
            'cross_origin_embedder_policy' => 'Consider COEP for apps that need strong cross-origin isolation.',
            'cross_origin_opener_policy' => 'Consider COOP for apps that need strong cross-origin isolation.',
            'cross_origin_resource_policy' => 'Consider CORP for sensitive cross-origin resources.',
            default => 'Review this browser security header.',
        };
    }

    /**
     * @return list<array{name: string, domain: string|null, path: string|null, secure: bool, http_only: bool, same_site: string|null, expires_at: Carbon|null, persistent: bool, host_only: bool}>
     */
    private function parseCookies(array $headers, string $defaultDomain): array
    {
        $setCookies = $this->headerValues($headers, 'set-cookie');
        $cookies = [];

        foreach ($setCookies as $line) {
            foreach (preg_split('/,(?=[^;,]+=)/', $line) ?: [] as $cookieLine) {
                $parts = array_map('trim', explode(';', $cookieLine));
                $nameValue = array_shift($parts);

                if (! is_string($nameValue) || ! str_contains($nameValue, '=')) {
                    continue;
                }

                [$name] = explode('=', $nameValue, 2);
                $cookie = [
                    'name' => $name,
                    'domain' => null,
                    'path' => null,
                    'secure' => false,
                    'http_only' => false,
                    'same_site' => null,
                    'expires_at' => null,
                    'persistent' => false,
                    'host_only' => true,
                ];

                foreach ($parts as $part) {
                    $lower = strtolower($part);

                    if ($lower === 'secure') {
                        $cookie['secure'] = true;
                    } elseif ($lower === 'httponly') {
                        $cookie['http_only'] = true;
                    } elseif (str_starts_with($lower, 'domain=')) {
                        $cookie['domain'] = ltrim(substr($part, 7), '.');
                        $cookie['host_only'] = false;
                    } elseif (str_starts_with($lower, 'path=')) {
                        $cookie['path'] = substr($part, 5);
                    } elseif (str_starts_with($lower, 'samesite=')) {
                        $cookie['same_site'] = substr($part, 9);
                    } elseif (str_starts_with($lower, 'expires=')) {
                        $timestamp = strtotime(substr($part, 8));
                        $cookie['expires_at'] = $timestamp === false ? null : Carbon::createFromTimestamp($timestamp);
                        $cookie['persistent'] = $cookie['expires_at'] !== null;
                    } elseif (str_starts_with($lower, 'max-age=')) {
                        $maxAge = (int) substr($part, 8);
                        $cookie['expires_at'] = Carbon::now()->addSeconds($maxAge);
                        $cookie['persistent'] = $maxAge > 0;
                    }
                }

                $cookie['domain'] ??= $defaultDomain;
                $cookies[] = $cookie;
            }
        }

        return $cookies;
    }

    /**
     * @return array{title: string|null, description: string|null, generator: string|null, lang: string|null, doctype: string|null}
     */
    private function parseHtmlSignals(string $body): array
    {
        return [
            'title' => $this->match('/<title[^>]*>\s*(.*?)\s*<\/title>/is', $body),
            'description' => $this->match('/<meta\s+[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\'][^>]*>/i', $body),
            'generator' => $this->match('/<meta\s+[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\'][^>]*>/i', $body),
            'lang' => $this->match('/<html\s+[^>]*lang=["\']([^"\']+)["\']/i', $body),
            'doctype' => $this->match('/<!doctype\s+([^>]+)>/i', $body),
        ];
    }

    private function match(string $pattern, string $body): ?string
    {
        if (preg_match($pattern, $body, $matches) !== 1) {
            return null;
        }

        return trim(html_entity_decode(strip_tags((string) $matches[1])));
    }

    /**
     * @return list<string>
     */
    private function sensitiveRobotsPaths(string $body): array
    {
        $paths = [];

        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            if (preg_match('/^\s*disallow:\s*(\S+)/i', $line, $matches) !== 1) {
                continue;
            }

            $path = (string) $matches[1];

            if (preg_match('/admin|backup|private|secret|staging|dev|wp-admin|config|\.env/i', $path) === 1) {
                $paths[] = $path;
            }
        }

        return array_values(array_unique($paths));
    }

    private function trimBody(string $body): string
    {
        return substr($body, 0, (int) config('scanforge.discovery.max_body_bytes', 262144));
    }

    /**
     * @return array<string, string>
     */
    private function flattenHeaders(array $headers): array
    {
        $flat = [];

        foreach ($headers as $name => $values) {
            $flat[strtolower((string) $name)] = implode(', ', array_map('strval', (array) $values));
        }

        return $flat;
    }

    private function headerValue(array $headers, string $name): ?string
    {
        $values = $this->headerValues($headers, $name);

        return $values === [] ? null : implode(', ', $values);
    }

    /**
     * @return list<string>
     */
    private function headerValues(array $headers, string $name): array
    {
        foreach ($headers as $headerName => $values) {
            if (strtolower((string) $headerName) === strtolower($name)) {
                return array_values(array_map('strval', (array) $values));
            }
        }

        return [];
    }

    private function origin(Website $website): string
    {
        return $website->scheme.'://'.$website->host.($website->port === null ? '' : ':'.$website->port);
    }

    private function resolveRedirect(string $currentUrl, string $location): string
    {
        if (preg_match('#^https?://#i', $location) === 1) {
            return $location;
        }

        $scheme = (string) parse_url($currentUrl, PHP_URL_SCHEME);
        $host = (string) parse_url($currentUrl, PHP_URL_HOST);
        $port = parse_url($currentUrl, PHP_URL_PORT);
        $origin = $scheme.'://'.$host.($port === null ? '' : ':'.$port);

        return str_starts_with($location, '/') ? $origin.$location : $origin.'/'.ltrim($location, '/');
    }

    private function urlForPath(string $url, string $path): string
    {
        $scheme = (string) parse_url($url, PHP_URL_SCHEME);
        $host = (string) parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT);

        return $scheme.'://'.$host.($port === null ? '' : ':'.$port).$path;
    }

    private function isAllowedRedirectHost(Website $website, string $host): bool
    {
        return $host === $website->host || str_ends_with($host, '.'.$website->root_domain);
    }
}
