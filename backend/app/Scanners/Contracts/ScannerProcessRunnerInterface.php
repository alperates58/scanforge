<?php

namespace App\Scanners\Contracts;

use App\Scanners\Support\ScannerProcessResult;

interface ScannerProcessRunnerInterface
{
    /**
     * @param list<string> $command
     * @param callable(): bool|null $shouldCancel
     */
    public function run(array $command, int $timeoutSeconds, string $workingDirectory, ?callable $shouldCancel = null): ScannerProcessResult;
}
