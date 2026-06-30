<?php

namespace App\Scanners;

use App\Scanners\Contracts\ScannerInterface;
use App\Scanners\Mock\MockScanner;
use Illuminate\Contracts\Container\Container;
use InvalidArgumentException;

class ScannerFactory
{
    public function __construct(private readonly Container $container)
    {
    }

    public function make(string $scannerKey): ScannerInterface
    {
        $adapterClass = config("scanners.adapters.{$scannerKey}");

        if (! is_string($adapterClass) || $adapterClass === '') {
            if ((bool) config('scanners.fallback_to_mock', true)) {
                return $this->container->make(MockScanner::class);
            }

            throw new InvalidArgumentException("No scanner adapter registered for [{$scannerKey}].");
        }

        $adapter = $this->container->make($adapterClass);

        if (! $adapter instanceof ScannerInterface) {
            throw new InvalidArgumentException("Scanner adapter [{$adapterClass}] must implement ScannerInterface.");
        }

        return $adapter;
    }
}
