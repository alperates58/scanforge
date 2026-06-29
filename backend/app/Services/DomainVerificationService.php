<?php

namespace App\Services;

use App\Models\DomainVerification;
use App\Models\Website;
use App\Support\VerificationMethods;
use App\Support\VerificationStatuses;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;

class DomainVerificationService
{
    public function __construct(
        private readonly DnsResolver $dnsResolver,
        private readonly TargetUrlGuard $targetUrlGuard,
        private readonly VerificationTokenService $tokenService,
    ) {
    }

    /**
     * @return array{token: string, methods: list<array<string, mixed>>}
     */
    public function instructions(Website $website): array
    {
        $token = $this->ensureRecords($website);
        $expectedValue = 'scanforge-verify='.$token;

        return [
            'token' => $token,
            'methods' => [
                [
                    'method' => VerificationMethods::DNS_TXT,
                    'label' => 'DNS TXT',
                    'host' => $website->host,
                    'record_type' => 'TXT',
                    'record_value' => $expectedValue,
                    'status' => $this->statusFor($website, VerificationMethods::DNS_TXT),
                ],
                [
                    'method' => VerificationMethods::HTML_FILE,
                    'label' => 'HTML File',
                    'path' => '/.well-known/scanforge-verify.txt',
                    'expected_body' => $expectedValue,
                    'status' => $this->statusFor($website, VerificationMethods::HTML_FILE),
                ],
                [
                    'method' => VerificationMethods::META_TAG,
                    'label' => 'Meta Tag',
                    'tag' => '<meta name="scanforge-verification" content="'.$token.'">',
                    'status' => $this->statusFor($website, VerificationMethods::META_TAG),
                ],
            ],
        ];
    }

    /**
     * @return array{verified: bool, verified_method: string|null, methods: list<array<string, mixed>>}
     */
    public function check(Website $website): array
    {
        $this->targetUrlGuard->assertPublicHost((string) $website->host);

        $token = $this->ensureRecords($website);
        $checkedAt = Carbon::now();

        $checks = [
            VerificationMethods::DNS_TXT => $this->checkDnsTxt($website, $token),
            VerificationMethods::HTML_FILE => $this->checkHtmlFile($website, $token),
            VerificationMethods::META_TAG => $this->checkMetaTag($website, $token),
        ];

        $verifiedMethod = null;
        $methodResults = [];

        foreach ($checks as $method => $result) {
            $status = $result['ok'] ? VerificationStatuses::VERIFIED : VerificationStatuses::FAILED;

            DomainVerification::query()
                ->where('website_id', $website->id)
                ->where('method', $method)
                ->update([
                    'status' => $status,
                    'checked_at' => $checkedAt,
                    'verified_at' => $result['ok'] ? $checkedAt : null,
                    'last_error' => $result['ok'] ? null : $result['error'],
                    'evidence' => $result['evidence'],
                ]);

            if ($result['ok'] && $verifiedMethod === null) {
                $verifiedMethod = $method;
            }

            $methodResults[] = [
                'method' => $method,
                'status' => $status,
                'checked_at' => $checkedAt->toISOString(),
                'error' => $result['ok'] ? null : $result['error'],
            ];
        }

        $website->forceFill([
            'verification_last_checked_at' => $checkedAt,
            'verification_status' => $verifiedMethod === null ? VerificationStatuses::FAILED : VerificationStatuses::VERIFIED,
            'verification_method' => $verifiedMethod,
            'ownership_verified_at' => $verifiedMethod === null ? $website->ownership_verified_at : $checkedAt,
            'verified_at' => $verifiedMethod === null ? $website->verified_at : $checkedAt,
            'status' => $verifiedMethod === null ? 'pending_verification' : 'verified',
        ])->save();

        return [
            'verified' => $verifiedMethod !== null,
            'verified_method' => $verifiedMethod,
            'methods' => $methodResults,
        ];
    }

    public function ensureRecords(Website $website): string
    {
        $token = $this->tokenService->ensureHash($website);
        $hash = $this->tokenService->hashToken($token);

        foreach (VerificationMethods::all() as $method) {
            DomainVerification::query()->firstOrCreate(
                [
                    'website_id' => $website->id,
                    'method' => $method,
                ],
                [
                    'verification_token_hash' => $hash,
                    'status' => VerificationStatuses::PENDING,
                    'expires_at' => Carbon::now()->addDays(30),
                ]
            );
        }

        DomainVerification::query()
            ->where('website_id', $website->id)
            ->whereNull('verification_token_hash')
            ->update(['verification_token_hash' => $hash]);

        return $token;
    }

    private function statusFor(Website $website, string $method): string
    {
        return (string) ($website->domainVerifications->firstWhere('method', $method)?->status ?? VerificationStatuses::PENDING);
    }

    /**
     * @return array{ok: bool, error: string|null, evidence: array<string, mixed>}
     */
    private function checkDnsTxt(Website $website, string $token): array
    {
        $expected = 'scanforge-verify='.$token;
        $records = $this->dnsResolver->txtRecords((string) $website->host);
        $normalizedRecords = array_map(fn (string $value): string => trim($value, "\" \t\n\r\0\x0B"), $records);
        $ok = in_array($expected, $normalizedRecords, true);

        return [
            'ok' => $ok,
            'error' => $ok ? null : 'dns_txt_record_not_found',
            'evidence' => [
                'record_count' => count($records),
                'matched' => $ok,
            ],
        ];
    }

    /**
     * @return array{ok: bool, error: string|null, evidence: array<string, mixed>}
     */
    private function checkHtmlFile(Website $website, string $token): array
    {
        $expected = 'scanforge-verify='.$token;
        $response = $this->fetchSameHost($website, '/.well-known/scanforge-verify.txt');

        if (! $response['ok']) {
            return [
                'ok' => false,
                'error' => $response['error'],
                'evidence' => $response['evidence'],
            ];
        }

        $body = trim($response['body']);
        $ok = hash_equals($expected, $body);

        return [
            'ok' => $ok,
            'error' => $ok ? null : 'html_file_body_mismatch',
            'evidence' => [
                ...$response['evidence'],
                'body_length' => strlen($body),
                'matched' => $ok,
            ],
        ];
    }

    /**
     * @return array{ok: bool, error: string|null, evidence: array<string, mixed>}
     */
    private function checkMetaTag(Website $website, string $token): array
    {
        $response = $this->fetchSameHost($website, '/');

        if (! $response['ok']) {
            return [
                'ok' => false,
                'error' => $response['error'],
                'evidence' => $response['evidence'],
            ];
        }

        $ok = preg_match(
            '/<meta\s+[^>]*name=["\']scanforge-verification["\'][^>]*content=["\']'.preg_quote($token, '/').'["\'][^>]*>/i',
            $response['body']
        ) === 1;

        return [
            'ok' => $ok,
            'error' => $ok ? null : 'meta_tag_not_found',
            'evidence' => [
                ...$response['evidence'],
                'body_length' => strlen($response['body']),
                'matched' => $ok,
            ],
        ];
    }

    /**
     * @return array{ok: bool, body: string, error: string|null, evidence: array<string, mixed>}
     */
    private function fetchSameHost(Website $website, string $path): array
    {
        $url = $this->origin($website).$path;
        $redirects = 0;
        $maxRedirects = (int) config('scanforge.verification.max_redirects', 3);
        $timeout = (int) config('scanforge.verification.timeout_seconds', 5);

        while ($redirects <= $maxRedirects) {
            $response = Http::timeout($timeout)
                ->withoutRedirecting()
                ->accept('text/html, text/plain, */*')
                ->get($url);

            if ($response->redirect()) {
                $location = $response->header('Location');

                if (! is_string($location) || $location === '') {
                    return $this->failedHttpEvidence('redirect_without_location', $response->status(), $url, $redirects);
                }

                $nextUrl = $this->resolveRedirect($url, $location);
                $nextHost = strtolower((string) parse_url($nextUrl, PHP_URL_HOST));
                $nextScheme = strtolower((string) parse_url($nextUrl, PHP_URL_SCHEME));

                if ($nextHost !== $website->host || ! in_array($nextScheme, ['http', 'https'], true)) {
                    return $this->failedHttpEvidence('redirect_left_verified_host', $response->status(), $url, $redirects);
                }

                $url = $nextUrl;
                $redirects++;
                continue;
            }

            if (! $response->successful()) {
                return $this->failedHttpEvidence('http_status_not_successful', $response->status(), $url, $redirects);
            }

            return [
                'ok' => true,
                'body' => $response->body(),
                'error' => null,
                'evidence' => [
                    'status' => $response->status(),
                    'redirects' => $redirects,
                    'final_host' => (string) parse_url($url, PHP_URL_HOST),
                ],
            ];
        }

        return $this->failedHttpEvidence('redirect_limit_exceeded', null, $url, $redirects);
    }

    /**
     * @return array{ok: false, body: string, error: string, evidence: array<string, mixed>}
     */
    private function failedHttpEvidence(string $error, ?int $status, string $url, int $redirects): array
    {
        return [
            'ok' => false,
            'body' => '',
            'error' => $error,
            'evidence' => [
                'status' => $status,
                'redirects' => $redirects,
                'final_host' => (string) parse_url($url, PHP_URL_HOST),
            ],
        ];
    }

    private function origin(Website $website): string
    {
        $port = $website->port === null ? '' : ':'.$website->port;

        return $website->scheme.'://'.$website->host.$port;
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

        if (str_starts_with($location, '/')) {
            return $origin.$location;
        }

        return $origin.'/'.ltrim($location, '/');
    }
}
