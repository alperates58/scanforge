<?php

namespace App\Fingerprinting\Plugins;

use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\RuleGroup;

class WordPressPlugin extends AbstractFingerprintPlugin
{
    public function key(): string
    {
        return 'wordpress';
    }

    public function label(): string
    {
        return 'WordPress';
    }

    public function ruleGroups(): array
    {
        return [
            new RuleGroup(
                technologyKey: 'wordpress',
                technologyName: 'WordPress',
                category: 'cms',
                rules: [
                    $this->rule('wordpress-generator-meta', 'generator_meta', 'generator', 95, 'Generator meta references WordPress.', fn (FingerprintContext $context) => $this->contains($context->generator(), 'wordpress', '/wordpress\s+([0-9][0-9.]+)/i')),
                    $this->rule('wordpress-wp-content', 'html', 'wp-content', 66, 'HTML references wp-content assets.', fn (FingerprintContext $context) => $context->bodyContains('wp-content') ? ['source_value' => 'wp-content'] : null),
                    $this->rule('wordpress-cookie', 'cookie', 'wordpress_', 74, 'WordPress cookie prefix is present.', fn (FingerprintContext $context) => $context->hasCookieContaining('wordpress_') ? ['source_value' => 'wordpress cookie'] : null),
                    $this->rule('wordpress-rest-api', 'html', 'wp-json', 64, 'HTML references WordPress REST API.', fn (FingerprintContext $context) => $context->bodyContains('wp-json') ? ['source_value' => 'wp-json'] : null),
                    $this->rule('wordpress-login-path', 'html', 'wp-login.php', 54, 'HTML references WordPress login path.', fn (FingerprintContext $context) => $context->bodyContains('wp-login.php') ? ['source_value' => 'wp-login.php'] : null),
                    $this->rule('wordpress-rss-generator', 'html', 'rss-generator', 58, 'Body contains WordPress RSS generator marker.', fn (FingerprintContext $context) => $context->bodyContains('generator="wordpress') ? ['source_value' => 'rss generator'] : null),
                ],
                parents: ['php', 'nginx', 'apache', 'openresty', 'litespeed'],
                coverageCategory: 'cms',
                cpeVendor: 'wordpress',
                cpeProduct: 'wordpress',
            ),
        ];
    }
}
