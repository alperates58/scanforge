<?php

namespace App\Fingerprinting\Plugins;

use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\RuleGroup;

class NginxPlugin extends AbstractFingerprintPlugin
{
    public function key(): string
    {
        return 'nginx';
    }

    public function label(): string
    {
        return 'Nginx';
    }

    public function ruleGroups(): array
    {
        return [
            new RuleGroup(
                technologyKey: 'nginx',
                technologyName: 'Nginx',
                category: 'server',
                rules: [
                    $this->rule('nginx-server-header', 'server', 'server', 82, 'Server header references Nginx.', fn (FingerprintContext $context) => $this->contains($context->server(), 'nginx', '/nginx\/([0-9][0-9.a-zA-Z-]*)/')),
                    $this->rule('nginx-via-header', 'header', 'via', 54, 'Via header references Nginx.', fn (FingerprintContext $context) => $this->header($context, 'via', 'nginx')),
                    $this->rule('nginx-body-default', 'html', 'body', 42, 'Default Nginx response body marker is present.', fn (FingerprintContext $context) => $context->bodyContains('nginx') ? ['source_value' => 'nginx body marker'] : null),
                ],
                parents: ['cloudflare', 'fastly', 'cloudfront', 'akamai', 'bunny'],
                conflictsWith: ['apache', 'caddy', 'litespeed', 'iis'],
                coverageCategory: 'server',
                cpeVendor: 'nginx',
                cpeProduct: 'nginx',
                conflictGroup: 'http_server',
            ),
        ];
    }
}
