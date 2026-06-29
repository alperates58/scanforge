<?php

namespace App\Fingerprinting\Plugins;

use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\RuleGroup;

class PhpPlugin extends AbstractFingerprintPlugin
{
    public function key(): string
    {
        return 'php';
    }

    public function label(): string
    {
        return 'PHP';
    }

    public function ruleGroups(): array
    {
        return [
            new RuleGroup(
                technologyKey: 'php',
                technologyName: 'PHP',
                category: 'language',
                rules: [
                    $this->rule('php-powered-by', 'header', 'x-powered-by', 82, 'X-Powered-By references PHP.', fn (FingerprintContext $context) => $this->header($context, 'x-powered-by', 'php', '/php\/([0-9][0-9.]+)/i')),
                    $this->rule('php-session-cookie', 'cookie', 'phpsessid', 66, 'PHP session cookie is present.', fn (FingerprintContext $context) => $context->hasCookie('phpsessid') ? ['source_value' => 'PHPSESSID'] : null),
                    $this->rule('php-body-marker', 'html', 'php', 35, 'Body references PHP.', fn (FingerprintContext $context) => $context->bodyContains('.php') ? ['source_value' => '.php'] : null),
                ],
                parents: ['nginx', 'apache', 'openresty', 'litespeed', 'iis'],
                coverageCategory: 'language',
                cpeVendor: 'php',
                cpeProduct: 'php',
            ),
        ];
    }
}
