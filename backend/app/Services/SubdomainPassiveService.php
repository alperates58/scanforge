<?php

namespace App\Services;

use App\Models\AssetDiscovery;
use App\Models\SslCertificate;
use App\Models\Subdomain;
use App\Models\Website;
use Illuminate\Support\Carbon;

class SubdomainPassiveService
{
    public function __construct(private readonly DnsResolver $dnsResolver)
    {
    }

    /**
     * @return array{total: int, hosts: list<string>}
     */
    public function discover(Website $website, AssetDiscovery $discovery, ?SslCertificate $certificate = null): array
    {
        $hosts = [
            ['host' => (string) $website->host, 'source' => 'verified_host'],
            ['host' => 'www.'.(string) $website->root_domain, 'source' => 'common_www'],
        ];

        foreach (($certificate?->san ?? []) as $sanHost) {
            if (is_string($sanHost) && str_ends_with($sanHost, '.'.$website->root_domain)) {
                $hosts[] = ['host' => $sanHost, 'source' => 'certificate_san'];
            }
        }

        $now = Carbon::now();
        $created = [];

        foreach (array_unique($hosts, SORT_REGULAR) as $candidate) {
            $host = strtolower(trim($candidate['host']));

            if ($host === '' || (! str_ends_with($host, '.'.$website->root_domain) && $host !== $website->root_domain)) {
                continue;
            }

            $resolved = $this->dnsResolver->resolveIps($host) !== [];

            Subdomain::query()->updateOrCreate(
                [
                    'website_id' => $website->id,
                    'host' => $host,
                    'source' => $candidate['source'],
                ],
                [
                    'workspace_id' => $website->workspace_id,
                    'asset_discovery_id' => $discovery->id,
                    'resolved' => $resolved,
                    'first_seen_at' => $now,
                    'last_seen_at' => $now,
                ]
            );

            $created[] = $host;
        }

        return [
            'total' => count(array_unique($created)),
            'hosts' => array_values(array_unique($created)),
        ];
    }
}
