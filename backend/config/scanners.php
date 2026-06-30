<?php

use App\Scanners\Mock\MockScanner;
use App\Scanners\Nuclei\NucleiScanner;

return [
    'adapters' => [
        'nuclei' => NucleiScanner::class,
        'mock' => MockScanner::class,
    ],

    'fallback_to_mock' => env('SCANNER_MOCK_WORKER_ENABLED', true),
];
