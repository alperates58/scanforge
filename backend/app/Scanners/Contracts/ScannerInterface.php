<?php

namespace App\Scanners\Contracts;

use App\Models\ScanJob;

interface ScannerInterface
{
    /**
     * @return array<string, mixed>
     */
    public function execute(ScanJob $scanJob): array;

    public function cancel(ScanJob $scanJob): void;

    /**
     * @return array{valid: bool, errors: list<string>}
     */
    public function validate(ScanJob $scanJob): array;

    public function supports(string $scannerKey, ?string $scanModule = null): bool;
}
