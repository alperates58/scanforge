<?php

namespace App\Fingerprinting\Plugins;

use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\RuleGroup;

class CloudflarePlugin extends AbstractFingerprintPlugin
{
    public function key(): string
    {
        return 'cloudflare';
    }

    public function label(): string
    {
        return 'Cloudflare';
    }

    public function ruleGroups(): array
    {
        return [
            new RuleGroup(
                technologyKey: 'cloudflare',
                technologyName: 'Cloudflare',
                category: 'cdn',
                rules: [
                    $this->rule('cf-ray-header', 'header', 'cf-ray', 82, 'Cloudflare CF-Ray response header is present.', fn (FingerprintContext $context) => $this->header($context, 'cf-ray')),
                    $this->rule('cf-cache-status-header', 'header', 'cf-cache-status', 78, 'Cloudflare cache status header is present.', fn (FingerprintContext $context) => $this->header($context, 'cf-cache-status')),
                    $this->rule('cloudflare-server', 'server', 'server', 75, 'Server header references Cloudflare.', fn (FingerprintContext $context) => $this->contains($context->server(), 'cloudflare')),
                    $this->rule('cloudflare-cookie', 'cookie', '__cf_bm', 72, 'Cloudflare bot management cookie is present.', fn (FingerprintContext $context) => $context->hasCookie('__cf_bm') ? ['source_value' => '__cf_bm'] : null),
                    $this->rule('cloudflare-dns', 'dns', 'dns_record', 62, 'DNS records reference Cloudflare.', fn (FingerprintContext $context) => $context->dnsContains('cloudflare') ? ['source_value' => 'cloudflare dns evidence'] : null),
                ],
                coverageCategory: 'cdn',
            ),
        ];
    }
}
