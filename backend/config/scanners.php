<?php

use App\Scanners\Mock\MockScanner;
use App\Scanners\Native\CookieSecurityScanner;
use App\Scanners\Native\DnsSecurityScanner;
use App\Scanners\Native\HttpHeaderScanner;
use App\Scanners\Native\SslTlsScanner;
use App\Scanners\Nuclei\NucleiScanner;
use App\Scanners\Native\CmsScannerAdapter;

return [
    'adapters' => [
        'nuclei' => NucleiScanner::class,
        'mock' => MockScanner::class,
        'ssl_tls' => SslTlsScanner::class,
        'dns_security' => DnsSecurityScanner::class,
        'http_headers' => HttpHeaderScanner::class,
        'cookie_security' => CookieSecurityScanner::class,
        'cms_scanner' => CmsScannerAdapter::class,
    ],

    'fallback_to_mock' => env('SCANNER_MOCK_WORKER_ENABLED', true),
];
