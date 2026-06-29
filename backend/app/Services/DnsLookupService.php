<?php

namespace App\Services;

use App\Models\AssetDiscovery;
use App\Models\DnsRecord;
use App\Models\IpAddress;
use App\Models\Website;
use Illuminate\Support\Carbon;

class DnsLookupService
{
    public function __construct(
        private readonly DnsResolver $dnsResolver,
        private readonly IpEnrichmentService $ipEnrichmentService,
    ) {
    }

    /**
     * @return array{total_records: int, total_ips: int, has_private_ip: bool, private_ips: list<string>, ips: list<string>}
     */
    public function discover(Website $website, AssetDiscovery $discovery): array
    {
        $now = Carbon::now();
        $records = $this->normalizeRecords((string) $website->host);
        $ips = [];

        foreach ($records as $record) {
            DnsRecord::query()->create([
                'workspace_id' => $website->workspace_id,
                'website_id' => $website->id,
                'asset_discovery_id' => $discovery->id,
                'type' => $record['type'],
                'name' => $record['name'],
                'value' => $record['value'],
                'ttl' => $record['ttl'],
                'priority' => $record['priority'],
                'source' => $record['source'],
                'first_seen_at' => $now,
                'last_seen_at' => $now,
            ]);

            if (in_array($record['type'], ['A', 'AAAA'], true)) {
                $ips[] = $record['value'];
            }
        }

        $ips = array_values(array_unique($ips));
        $privateIps = [];

        foreach ($ips as $ip) {
            $enrichment = $this->ipEnrichmentService->enrich($ip);

            if (! $enrichment['is_public']) {
                $privateIps[] = $ip;
            }

            IpAddress::query()->create([
                'workspace_id' => $website->workspace_id,
                'website_id' => $website->id,
                'asset_discovery_id' => $discovery->id,
                'ip' => $ip,
                'ip_version' => $enrichment['ip_version'],
                'is_public' => $enrichment['is_public'],
                'reverse_dns' => $enrichment['reverse_dns'],
                'asn' => $enrichment['asn'],
                'asn_org' => $enrichment['asn_org'],
                'country_code' => $enrichment['country_code'],
                'region' => $enrichment['region'],
                'city' => $enrichment['city'],
                'provider' => $enrichment['provider'],
                'source' => $enrichment['source'],
                'first_seen_at' => $now,
                'last_seen_at' => $now,
            ]);
        }

        return [
            'total_records' => count($records),
            'total_ips' => count($ips),
            'has_private_ip' => $privateIps !== [],
            'private_ips' => $privateIps,
            'ips' => $ips,
        ];
    }

    /**
     * @return list<array{type: string, name: string, value: string, ttl: int|null, priority: int|null, source: string}>
     */
    private function normalizeRecords(string $host): array
    {
        $records = [];
        $rawRecords = $this->dnsResolver->records($host, ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA']);

        foreach ($rawRecords as $record) {
            $type = strtoupper((string) ($record['type'] ?? ''));
            $value = $this->recordValue($type, $record);

            if ($type === '' || $value === null || $value === '') {
                continue;
            }

            $records[] = [
                'type' => $type,
                'name' => (string) ($record['host'] ?? $host),
                'value' => $value,
                'ttl' => isset($record['ttl']) ? (int) $record['ttl'] : null,
                'priority' => isset($record['pri']) ? (int) $record['pri'] : null,
                'source' => 'dns_get_record',
            ];
        }

        if (! collect($records)->contains(fn (array $record): bool => in_array($record['type'], ['A', 'AAAA'], true))) {
            foreach ($this->dnsResolver->resolveIps($host) as $ip) {
                $records[] = [
                    'type' => str_contains($ip, ':') ? 'AAAA' : 'A',
                    'name' => $host,
                    'value' => $ip,
                    'ttl' => null,
                    'priority' => null,
                    'source' => 'dns_resolver',
                ];
            }
        }

        return array_values(array_unique($records, SORT_REGULAR));
    }

    /**
     * @param array<string, mixed> $record
     */
    private function recordValue(string $type, array $record): ?string
    {
        return match ($type) {
            'A' => isset($record['ip']) ? (string) $record['ip'] : null,
            'AAAA' => isset($record['ipv6']) ? (string) $record['ipv6'] : null,
            'CNAME', 'NS' => isset($record['target']) ? rtrim((string) $record['target'], '.') : null,
            'MX' => isset($record['target']) ? rtrim((string) $record['target'], '.') : null,
            'TXT' => isset($record['txt']) ? (string) $record['txt'] : null,
            'CAA' => trim(((string) ($record['flags'] ?? '')).' '.((string) ($record['tag'] ?? '')).' '.((string) ($record['value'] ?? ''))),
            default => null,
        };
    }
}
