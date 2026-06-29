<?php

namespace App\Fingerprinting\Plugins;

use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\RuleGroup;

class ReactPlugin extends AbstractFingerprintPlugin
{
    public function key(): string
    {
        return 'react';
    }

    public function label(): string
    {
        return 'React';
    }

    public function ruleGroups(): array
    {
        return [
            new RuleGroup(
                technologyKey: 'react',
                technologyName: 'React',
                category: 'frontend',
                rules: [
                    $this->rule('react-root-marker', 'html', 'root', 52, 'HTML contains common React root marker.', fn (FingerprintContext $context) => $context->bodyContains('data-reactroot') || $context->bodyContains('id="root"') ? ['source_value' => 'react root'] : null),
                    $this->rule('react-body-marker', 'html', 'react', 38, 'HTML references React.', fn (FingerprintContext $context) => $context->bodyContains('react') ? ['source_value' => 'react'] : null),
                    $this->rule('react-static-js', 'js_asset', 'static/js', 42, 'JS asset path resembles React build output.', fn (FingerprintContext $context) => $context->bodyContains('/static/js/') ? ['source_value' => '/static/js/'] : null),
                ],
                coverageCategory: 'frontend',
            ),
        ];
    }
}
