<?php

namespace App\Scanners\Support;

class ScannerProcessResult
{
    public function __construct(
        public readonly int $exitCode,
        public readonly string $stdout,
        public readonly string $stderr,
        public readonly bool $timedOut = false,
        public readonly bool $cancelled = false,
        public readonly int $durationMs = 0,
    ) {
    }

    public function successful(): bool
    {
        return $this->exitCode === 0 && ! $this->timedOut && ! $this->cancelled;
    }
}
