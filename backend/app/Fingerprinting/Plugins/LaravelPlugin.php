<?php

namespace App\Fingerprinting\Plugins;

use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\RuleGroup;

class LaravelPlugin extends AbstractFingerprintPlugin
{
    public function key(): string
    {
        return 'laravel';
    }

    public function label(): string
    {
        return 'Laravel';
    }

    public function ruleGroups(): array
    {
        return [
            new RuleGroup(
                technologyKey: 'laravel',
                technologyName: 'Laravel',
                category: 'framework',
                rules: [
                    $this->rule('laravel-session-cookie', 'cookie', 'laravel_session', 78, 'Laravel session cookie is present.', fn (FingerprintContext $context) => $context->hasCookie('laravel_session') ? ['source_value' => 'laravel_session'] : null),
                    $this->rule('laravel-header', 'header', 'x-laravel', 72, 'Laravel specific response header is present.', fn (FingerprintContext $context) => $this->header($context, 'x-laravel')),
                    $this->rule('laravel-csrf-meta', 'html', 'csrf-token', 48, 'Laravel-style CSRF meta marker is present.', fn (FingerprintContext $context) => $context->bodyContains('csrf-token') ? ['source_value' => 'csrf-token'] : null),
                    $this->rule('laravel-body-marker', 'html', 'body', 42, 'Body contains Laravel marker.', fn (FingerprintContext $context) => $context->bodyContains('laravel') ? ['source_value' => 'laravel body marker'] : null),
                ],
                parents: ['php', 'nginx', 'apache', 'openresty', 'litespeed'],
                coverageCategory: 'framework',
                cpeVendor: 'laravel',
                cpeProduct: 'laravel',
            ),
        ];
    }
}
