<?php

use App\Fingerprinting\Plugins\CloudflarePlugin;
use App\Fingerprinting\Plugins\CommonTechnologyPlugin;
use App\Fingerprinting\Plugins\LaravelPlugin;
use App\Fingerprinting\Plugins\NextJsPlugin;
use App\Fingerprinting\Plugins\NginxPlugin;
use App\Fingerprinting\Plugins\PhpPlugin;
use App\Fingerprinting\Plugins\ReactPlugin;
use App\Fingerprinting\Plugins\WordPressPlugin;

return [
    'analysis_version' => env('SCANFORGE_FINGERPRINT_ANALYSIS_VERSION', 'fingerprint-v1'),

    'plugins' => [
        CloudflarePlugin::class,
        NginxPlugin::class,
        PhpPlugin::class,
        LaravelPlugin::class,
        WordPressPlugin::class,
        NextJsPlugin::class,
        ReactPlugin::class,
        CommonTechnologyPlugin::class,
    ],

    'source_priorities' => [
        'generator_meta' => 95,
        'ssl' => 85,
        'header' => 80,
        'server' => 80,
        'cookie' => 75,
        'dns' => 70,
        'response' => 70,
        'body' => 60,
        'html' => 60,
        'redirect' => 55,
        'favicon' => 50,
        'js_asset' => 45,
    ],

    'coverage_categories' => [
        'server',
        'language',
        'framework',
        'cms',
        'cdn',
        'hosting',
        'database',
        'frontend',
        'waf',
        'analytics',
    ],

    'conflict_threshold' => 75,
];
