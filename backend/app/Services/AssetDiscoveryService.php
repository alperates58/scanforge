<?php

namespace App\Services;

use App\Models\AssetDiscovery;
use App\Models\CookieObservation;
use App\Models\DnsRecord;
use App\Models\DomainWhoisSnapshot;
use App\Models\Finding;
use App\Models\HttpObservation;
use App\Models\IpAddress;
use App\Models\SecurityHeaderObservation;
use App\Models\SslCertificate;
use App\Models\Subdomain;
use App\Models\TechnologyFingerprint;
use App\Models\Website;
use App\Support\DiscoveryStatuses;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Carbon;
use Throwable;

class AssetDiscoveryService
{
    public function __construct(
        private readonly DnsLookupService $dnsLookupService,
        private readonly HttpObservationService $httpObservationService,
        private readonly SslCertificateService $sslCertificateService,
        private readonly WhoisLookupService $whoisLookupService,
        private readonly SubdomainPassiveService $subdomainPassiveService,
        private readonly PassiveFindingService $passiveFindingService,
        private readonly TechnologyHintService $technologyHintService,
        private readonly DiscoveryScoreService $discoveryScoreService,
    ) {
    }

    public function run(Website $website): AssetDiscovery
    {
        if (! $website->isVerified()) {
            throw new AuthorizationException('Asset discovery requires a verified website.');
        }

        $started = Carbon::now();
        $discovery = AssetDiscovery::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'status' => DiscoveryStatuses::RUNNING,
            'started_at' => $started,
        ]);

        try {
            $dns = $this->dnsLookupService->discover($website, $discovery);
            $discovery->forceFill([
                'dns_completed_at' => Carbon::now(),
                'total_dns_records' => $dns['total_records'],
                'total_ips' => $dns['total_ips'],
            ])->save();

            if ($dns['has_private_ip']) {
                $this->passiveFindingService->privateIpResolution($website, $discovery, $dns['private_ips']);

                return $this->finish($website, $discovery, DiscoveryStatuses::FAILED, [
                    'host' => $website->host,
                    'blocked' => true,
                    'error' => 'private_or_internal_ip_resolved',
                    'private_ips' => $dns['private_ips'],
                    'dns' => $this->dnsSummary($discovery),
                ], 'private_or_internal_ip_resolved');
            }

            $http = $this->httpObservationService->discover($website, $discovery);
            $discovery->forceFill([
                'http_completed_at' => Carbon::now(),
                'total_headers' => $http['total_headers'],
                'total_cookies' => $http['total_cookies'],
            ])->save();

            $sslCertificate = $this->sslCertificateService->discover($website, $discovery);
            $discovery->forceFill(['ssl_completed_at' => Carbon::now()])->save();

            $whois = $this->whoisLookupService->discover($website, $discovery);
            $discovery->forceFill(['whois_completed_at' => Carbon::now()])->save();

            $subdomains = $this->subdomainPassiveService->discover($website, $discovery, $sslCertificate);
            $httpObservation = $http['observation'] instanceof HttpObservation ? $http['observation'] : null;
            $technologyCount = $httpObservation
                ? $this->technologyHintService->detect($website, $discovery, $httpObservation, $http['cookies'], (string) $http['body_sample'])
                : 0;

            $findingCount = 0;
            $findingCount += $this->passiveFindingService->sslFindings($website, $discovery, $sslCertificate);

            if ($httpObservation) {
                $findingCount += $this->passiveFindingService->httpFindings($website, $discovery, $httpObservation, $http['security_headers'], $http['cookies'], $http['robots']);
            }

            $score = $this->discoveryScoreService->score($website, $httpObservation, $sslCertificate, $http['security_headers'], $http['cookies']);
            $summary = $this->buildSummary($website, $discovery, $http, $sslCertificate, $whois, $subdomains, $score);

            $discovery->forceFill([
                'technologies_detected' => $technologyCount,
                'total_findings' => $findingCount,
                'analysis_required' => true,
                'discovery_score' => $score,
            ])->save();

            return $this->finish($website, $discovery, DiscoveryStatuses::COMPLETED, $summary);
        } catch (Throwable $exception) {
            return $this->finish($website, $discovery, DiscoveryStatuses::FAILED, [
                'host' => $website->host,
                'error' => class_basename($exception),
            ], class_basename($exception));
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function summary(Website $website): array
    {
        $latestDiscovery = AssetDiscovery::query()
            ->where('website_id', $website->id)
            ->latest('created_at')
            ->first();

        $latestHttp = HttpObservation::query()
            ->where('website_id', $website->id)
            ->latest('observed_at')
            ->first();

        $latestSsl = SslCertificate::query()
            ->where('website_id', $website->id)
            ->latest('observed_at')
            ->first();

        $latestWhois = DomainWhoisSnapshot::query()
            ->where('website_id', $website->id)
            ->latest('observed_at')
            ->first();

        return [
            'host' => $website->host,
            'last_discovery' => $latestDiscovery ? $this->discoveryData($latestDiscovery) : null,
            'ip_addresses' => IpAddress::query()->where('website_id', $website->id)->latest('last_seen_at')->limit(20)->get()->map(fn (IpAddress $ip): array => [
                'ip' => $ip->ip,
                'ip_version' => $ip->ip_version,
                'is_public' => $ip->is_public,
                'provider' => $ip->provider,
                'reverse_dns' => $ip->reverse_dns,
            ])->values()->all(),
            'dns_record_counts' => DnsRecord::query()
                ->where('website_id', $website->id)
                ->selectRaw('type, count(*) as total')
                ->groupBy('type')
                ->pluck('total', 'type'),
            'ssl' => $latestSsl ? [
                'available' => (bool) data_get($latestSsl->tls_summary, 'available', false),
                'days_remaining' => $latestSsl->days_remaining,
                'issuer' => $latestSsl->issuer,
                'valid_to' => $latestSsl->valid_to?->toISOString(),
            ] : null,
            'http' => $latestHttp ? [
                'status_code' => $latestHttp->status_code,
                'title' => $latestHttp->body_title ?? $latestHttp->title,
                'server' => $latestHttp->server_header,
                'powered_by' => $latestHttp->powered_by_header,
                'favicon_hash' => $latestHttp->favicon_hash,
                'final_url' => $latestHttp->final_url,
            ] : null,
            'security_headers' => $latestDiscovery ? $this->securityHeaderSummary($latestDiscovery) : [],
            'cookies' => $latestDiscovery ? $this->cookieSummary($latestDiscovery) : [],
            'robots' => data_get($latestDiscovery?->summary, 'robots'),
            'sitemap' => data_get($latestDiscovery?->summary, 'sitemap'),
            'whois' => $latestWhois ? [
                'registrar' => $latestWhois->registrar,
                'age_days' => $latestWhois->age_days,
                'status' => data_get($latestWhois->raw_summary, 'status'),
            ] : null,
            'subdomain_count' => Subdomain::query()->where('website_id', $website->id)->count(),
            'passive_findings' => Finding::query()
                ->where('website_id', $website->id)
                ->where('source_tool', 'scanforge-passive-discovery')
                ->latest()
                ->limit(10)
                ->get()
                ->map(fn (Finding $finding): array => [
                    'id' => $finding->id,
                    'title' => $finding->title,
                    'severity' => $finding->severity,
                    'status' => $finding->status,
                ])->values()->all(),
            'technologies' => TechnologyFingerprint::query()
                ->where('website_id', $website->id)
                ->whereIn('source', ['passive_discovery', 'fingerprint_engine'])
                ->orderByDesc('confidence_score')
                ->limit(20)
                ->get()
                ->map(fn (TechnologyFingerprint $technology): array => [
                    'technology_key' => $technology->technology_key,
                    'name' => $technology->name,
                    'category' => $technology->category,
                    'confidence_score' => $technology->confidence_score,
                    'quality_score' => $technology->quality_score ?? 0,
                    'detection_source' => $technology->detection_source,
                    'evidence' => $technology->evidence,
                ])->values()->all(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function discoveryData(AssetDiscovery $discovery): array
    {
        return [
            'id' => $discovery->id,
            'website_id' => $discovery->website_id,
            'status' => $discovery->status,
            'started_at' => $discovery->started_at?->toISOString(),
            'dns_completed_at' => $discovery->dns_completed_at?->toISOString(),
            'http_completed_at' => $discovery->http_completed_at?->toISOString(),
            'ssl_completed_at' => $discovery->ssl_completed_at?->toISOString(),
            'whois_completed_at' => $discovery->whois_completed_at?->toISOString(),
            'completed_at' => $discovery->completed_at?->toISOString(),
            'duration_ms' => $discovery->duration_ms,
            'discovery_score' => $discovery->discovery_score,
            'analysis_required' => $discovery->analysis_required,
            'metrics' => [
                'total_dns_records' => $discovery->total_dns_records,
                'total_ips' => $discovery->total_ips,
                'total_headers' => $discovery->total_headers,
                'total_cookies' => $discovery->total_cookies,
                'total_findings' => $discovery->total_findings,
                'technologies_detected' => $discovery->technologies_detected,
            ],
            'summary' => $discovery->summary,
            'error_message' => $discovery->error_message,
            'created_at' => $discovery->created_at?->toISOString(),
        ];
    }

    /**
     * @param array<string, mixed> $summary
     */
    private function finish(Website $website, AssetDiscovery $discovery, string $status, array $summary, ?string $error = null): AssetDiscovery
    {
        $completedAt = Carbon::now();
        $durationMs = $discovery->started_at ? (int) $discovery->started_at->diffInMilliseconds($completedAt) : null;

        $discovery->forceFill([
            'status' => $status,
            'completed_at' => $completedAt,
            'duration_ms' => $durationMs,
            'summary' => $summary,
            'error_message' => $error,
            'total_findings' => Finding::query()->where('asset_discovery_id', $discovery->id)->count(),
        ])->save();

        if ($status === DiscoveryStatuses::COMPLETED) {
            $website->forceFill([
                'discovery_completed_at' => $completedAt,
                'last_observed_at' => $completedAt,
                'security_score' => $discovery->discovery_score,
                'risk_score' => $discovery->discovery_score === null ? $website->risk_score : 100 - $discovery->discovery_score,
                'metadata' => [
                    ...(is_array($website->metadata) ? $website->metadata : []),
                    'last_discovery' => [
                        'id' => $discovery->id,
                        'completed_at' => $completedAt->toISOString(),
                        'score' => $discovery->discovery_score,
                    ],
                ],
            ])->save();
        }

        return $discovery->fresh();
    }

    /**
     * @param array<string, mixed> $http
     * @param array{total: int, hosts: list<string>} $subdomains
     * @return array<string, mixed>
     */
    private function buildSummary(Website $website, AssetDiscovery $discovery, array $http, ?SslCertificate $certificate, DomainWhoisSnapshot $whois, array $subdomains, int $score): array
    {
        $observation = $http['observation'];

        return [
            'host' => $website->host,
            'dns' => $this->dnsSummary($discovery),
            'ip_addresses' => IpAddress::query()->where('asset_discovery_id', $discovery->id)->pluck('ip')->values()->all(),
            'http' => $observation instanceof HttpObservation ? [
                'status_code' => $observation->status_code,
                'title' => $observation->body_title ?? $observation->title,
                'server' => $observation->server_header,
                'powered_by' => $observation->powered_by_header,
                'favicon_hash' => $observation->favicon_hash,
                'final_url' => $observation->final_url,
                'error' => $http['error'],
            ] : null,
            'security_headers' => $http['security_headers'],
            'cookies' => $this->cookieSummary($discovery),
            'robots' => $http['robots'],
            'sitemap' => $http['sitemap'],
            'ssl' => $certificate ? [
                'available' => (bool) data_get($certificate->tls_summary, 'available', false),
                'days_remaining' => $certificate->days_remaining,
                'valid_to' => $certificate->valid_to?->toISOString(),
                'fingerprint_sha256' => $certificate->fingerprint_sha256,
            ] : null,
            'whois' => [
                'status' => data_get($whois->raw_summary, 'status'),
                'registrar' => $whois->registrar,
                'age_days' => $whois->age_days,
            ],
            'subdomains' => $subdomains,
            'discovery_score' => $score,
        ];
    }

    /**
     * @return array<string, int>
     */
    private function dnsSummary(AssetDiscovery $discovery): array
    {
        return DnsRecord::query()
            ->where('asset_discovery_id', $discovery->id)
            ->selectRaw('type, count(*) as total')
            ->groupBy('type')
            ->pluck('total', 'type')
            ->map(fn ($value): int => (int) $value)
            ->all();
    }

    /**
     * @return array<string, mixed>
     */
    private function securityHeaderSummary(AssetDiscovery $discovery): array
    {
        return SecurityHeaderObservation::query()
            ->where('asset_discovery_id', $discovery->id)
            ->get()
            ->mapWithKeys(fn (SecurityHeaderObservation $header): array => [
                $header->header_key => [
                    'present' => $header->present,
                    'value' => $header->value,
                    'recommendation' => $header->recommendation,
                ],
            ])
            ->all();
    }

    /**
     * @return array<string, mixed>
     */
    private function cookieSummary(AssetDiscovery $discovery): array
    {
        $cookies = CookieObservation::query()->where('asset_discovery_id', $discovery->id)->get();

        return [
            'total' => $cookies->count(),
            'secure' => $cookies->where('secure', true)->count(),
            'http_only' => $cookies->where('http_only', true)->count(),
            'same_site' => $cookies->whereNotNull('same_site')->count(),
            'persistent' => $cookies->where('persistent', true)->count(),
        ];
    }
}
