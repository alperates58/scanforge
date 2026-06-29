<?php

namespace App\Fingerprinting\Support;

use App\Models\AssetDiscovery;
use App\Models\CookieObservation;
use App\Models\DnsRecord;
use App\Models\HttpObservation;
use App\Models\RedirectObservation;
use App\Models\SecurityHeaderObservation;
use App\Models\SslCertificate;
use App\Models\Website;

class FingerprintContext
{
    /**
     * @param list<CookieObservation> $cookies
     * @param list<DnsRecord> $dnsRecords
     * @param list<SecurityHeaderObservation> $securityHeaders
     * @param list<RedirectObservation> $redirects
     */
    public function __construct(
        public readonly Website $website,
        public readonly ?AssetDiscovery $assetDiscovery,
        public readonly ?HttpObservation $httpObservation,
        public readonly ?SslCertificate $sslCertificate,
        public readonly array $cookies,
        public readonly array $dnsRecords,
        public readonly array $securityHeaders,
        public readonly array $redirects,
        private readonly string $bodySample = '',
    ) {
    }

    public static function from(Website $website, ?AssetDiscovery $assetDiscovery = null, string $bodySample = ''): self
    {
        $assetDiscovery ??= AssetDiscovery::query()
            ->where('website_id', $website->id)
            ->latest('completed_at')
            ->latest('created_at')
            ->first();

        $httpObservation = HttpObservation::query()
            ->where('website_id', $website->id)
            ->when($assetDiscovery, fn ($query) => $query->where('asset_discovery_id', $assetDiscovery->id))
            ->latest('observed_at')
            ->first();

        $cookies = CookieObservation::query()
            ->where('website_id', $website->id)
            ->when($assetDiscovery, fn ($query) => $query->where('asset_discovery_id', $assetDiscovery->id))
            ->latest('observed_at')
            ->get()
            ->all();

        $dnsRecords = DnsRecord::query()
            ->where('website_id', $website->id)
            ->when($assetDiscovery, fn ($query) => $query->where('asset_discovery_id', $assetDiscovery->id))
            ->get()
            ->all();

        $securityHeaders = SecurityHeaderObservation::query()
            ->where('website_id', $website->id)
            ->when($assetDiscovery, fn ($query) => $query->where('asset_discovery_id', $assetDiscovery->id))
            ->get()
            ->all();

        $redirects = RedirectObservation::query()
            ->where('website_id', $website->id)
            ->when($assetDiscovery, fn ($query) => $query->where('asset_discovery_id', $assetDiscovery->id))
            ->orderBy('order')
            ->get()
            ->all();

        $sslCertificate = SslCertificate::query()
            ->where('website_id', $website->id)
            ->when($assetDiscovery, fn ($query) => $query->where('asset_discovery_id', $assetDiscovery->id))
            ->latest('observed_at')
            ->first();

        return new self($website, $assetDiscovery, $httpObservation, $sslCertificate, $cookies, $dnsRecords, $securityHeaders, $redirects, $bodySample);
    }

    /**
     * @return array<string, mixed>
     */
    public function headers(): array
    {
        return array_change_key_case($this->httpObservation?->headers ?? [], CASE_LOWER);
    }

    public function header(string $key): ?string
    {
        $value = $this->headers()[strtolower($key)] ?? null;

        if (is_array($value)) {
            return implode(', ', array_map('strval', $value));
        }

        return $value === null ? null : (string) $value;
    }

    public function hasHeader(string $key): bool
    {
        return $this->header($key) !== null;
    }

    public function headerContains(string $key, string $needle): bool
    {
        return str_contains(strtolower((string) $this->header($key)), strtolower($needle));
    }

    public function server(): string
    {
        return strtolower((string) $this->httpObservation?->server_header);
    }

    public function poweredBy(): string
    {
        return strtolower((string) $this->httpObservation?->powered_by_header);
    }

    public function generator(): string
    {
        return strtolower((string) $this->httpObservation?->generator_meta);
    }

    public function body(): string
    {
        return strtolower($this->bodySample);
    }

    public function title(): string
    {
        return strtolower((string) ($this->httpObservation?->body_title ?? $this->httpObservation?->title));
    }

    public function description(): string
    {
        return strtolower((string) $this->httpObservation?->body_description);
    }

    public function faviconHash(): ?string
    {
        return $this->httpObservation?->favicon_hash;
    }

    public function bodyContains(string $needle): bool
    {
        return str_contains($this->body(), strtolower($needle));
    }

    /**
     * @return list<string>
     */
    public function cookieNames(): array
    {
        return array_values(array_unique(array_map(
            fn (CookieObservation $cookie): string => strtolower($cookie->name),
            $this->cookies,
        )));
    }

    public function hasCookie(string $name): bool
    {
        return in_array(strtolower($name), $this->cookieNames(), true);
    }

    public function hasCookieContaining(string $needle): bool
    {
        $needle = strtolower($needle);

        foreach ($this->cookieNames() as $cookieName) {
            if (str_contains($cookieName, $needle)) {
                return true;
            }
        }

        return false;
    }

    public function dnsContains(string $needle): bool
    {
        $needle = strtolower($needle);

        foreach ($this->dnsRecords as $record) {
            if (str_contains(strtolower($record->value), $needle) || str_contains(strtolower($record->name), $needle)) {
                return true;
            }
        }

        return false;
    }

    public function redirectContains(string $needle): bool
    {
        $needle = strtolower($needle);

        foreach ($this->redirects as $redirect) {
            if (str_contains(strtolower($redirect->from_url), $needle) || str_contains(strtolower($redirect->to_url), $needle)) {
                return true;
            }
        }

        return false;
    }
}
