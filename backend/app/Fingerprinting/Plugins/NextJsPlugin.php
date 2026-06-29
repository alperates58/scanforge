<?php

namespace App\Fingerprinting\Plugins;

use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\RuleGroup;

class NextJsPlugin extends AbstractFingerprintPlugin
{
    public function key(): string
    {
        return 'nextjs';
    }

    public function label(): string
    {
        return 'Next.js';
    }

    public function ruleGroups(): array
    {
        return [
            new RuleGroup(
                technologyKey: 'nextjs',
                technologyName: 'Next.js',
                category: 'framework',
                rules: [
                    $this->rule('nextjs-cache-header', 'header', 'x-nextjs-cache', 78, 'Next.js cache header is present.', fn (FingerprintContext $context) => $this->header($context, 'x-nextjs-cache')),
                    $this->rule('nextjs-powered-by', 'header', 'x-powered-by', 70, 'X-Powered-By references Next.js.', fn (FingerprintContext $context) => $this->header($context, 'x-powered-by', 'next.js')),
                    $this->rule('nextjs-data-script', 'html', '__next_data__', 72, 'HTML contains __NEXT_DATA__ marker.', fn (FingerprintContext $context) => $context->bodyContains('__next_data__') ? ['source_value' => '__NEXT_DATA__'] : null),
                    $this->rule('nextjs-static-path', 'js_asset', '_next/static', 58, 'HTML references _next/static assets.', fn (FingerprintContext $context) => $context->bodyContains('/_next/static') ? ['source_value' => '/_next/static'] : null),
                ],
                parents: ['react', 'vercel', 'nginx', 'cloudflare'],
                coverageCategory: 'framework',
            ),
        ];
    }
}
