<?php

namespace App\Services;

class IpEnrichmentService
{
    /**
     * @return array<string, mixed>
     */
    public function enrich(string $ip): array
    {
        $reverseDns = null;

        if ((bool) config('scanforge.discovery.reverse_dns_enabled', false)) {
            $reverseDnsLookup = @gethostbyaddr($ip);
            $reverseDns = $reverseDnsLookup === false || $reverseDnsLookup === $ip ? null : $reverseDnsLookup;
        }

        return [
            'ip_version' => str_contains($ip, ':') ? 6 : 4,
            'is_public' => $this->isPublicIp($ip),
            'reverse_dns' => $reverseDns,
            'asn' => null,
            'asn_org' => null,
            'country_code' => null,
            'region' => null,
            'city' => null,
            'provider' => $this->providerHint($reverseDns),
            'source' => 'dns',
        ];
    }

    public function isPublicIp(string $ip): bool
    {
        return (bool) filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    private function providerHint(?string $reverseDns): ?string
    {
        if ($reverseDns === null) {
            return null;
        }

        $lower = strtolower($reverseDns);

        return match (true) {
            str_contains($lower, 'cloudflare') => 'Cloudflare',
            str_contains($lower, 'fastly') => 'Fastly',
            str_contains($lower, 'cloudfront') || str_contains($lower, 'amazonaws') => 'AWS / CloudFront',
            str_contains($lower, 'akamai') => 'Akamai',
            str_contains($lower, 'bunny') => 'Bunny',
            str_contains($lower, 'vercel') => 'Vercel',
            str_contains($lower, 'netlify') => 'Netlify',
            str_contains($lower, 'azure') => 'Azure',
            str_contains($lower, 'google') || str_contains($lower, '1e100') => 'Google',
            default => null,
        };
    }
}
