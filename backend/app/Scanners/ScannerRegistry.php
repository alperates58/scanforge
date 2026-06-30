<?php

namespace App\Scanners;

use App\Scanners\Contracts\ScannerInterface;

class ScannerRegistry
{
    public function __construct(private readonly ScannerResolver $scannerResolver)
    {
    }

    public function resolve(string $scannerKey, ?string $scanModule = null): ScannerInterface
    {
        return $this->scannerResolver->resolve($scannerKey, $scanModule);
    }

    public function has(string $scannerKey): bool
    {
        return array_key_exists($scannerKey, (array) config('scanners.adapters', []));
    }

    /** @return list<string> */
    public function keys(): array
    {
        return array_values(array_keys((array) config('scanners.adapters', [])));
    }
}
