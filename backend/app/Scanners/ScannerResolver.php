<?php

namespace App\Scanners;

use App\Scanners\Contracts\ScannerInterface;

class ScannerResolver
{
    public function __construct(private readonly ScannerFactory $scannerFactory)
    {
    }

    public function resolve(string $scannerKey, ?string $scanModule = null): ScannerInterface
    {
        $scanner = $this->scannerFactory->make($scannerKey);

        if (! $scanner->supports($scannerKey, $scanModule) && (bool) config('scanners.fallback_to_mock', true)) {
            return $this->scannerFactory->make('mock');
        }

        return $scanner;
    }
}
