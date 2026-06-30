<?php

namespace App\Scanners\Mock;

use App\Models\ScanJob;
use App\Scanners\Contracts\ScannerInterface;
use App\Services\MockExecutorService;

class MockScanner implements ScannerInterface
{
    public function __construct(private readonly MockExecutorService $mockExecutorService)
    {
    }

    public function execute(ScanJob $scanJob): array
    {
        $this->mockExecutorService->execute($scanJob->id);

        return ['mock' => true];
    }

    public function cancel(ScanJob $scanJob): void
    {
        $scanJob->forceFill([
            'cancel_requested_at' => now(),
            'cancellation_token' => $scanJob->cancellation_token ?: (string) str()->uuid(),
        ])->save();
    }

    public function validate(ScanJob $scanJob): array
    {
        return [
            'valid' => (bool) config('scanforge.scanner.mock_worker_enabled', true),
            'errors' => (bool) config('scanforge.scanner.mock_worker_enabled', true) ? [] : ['mock_worker_disabled'],
        ];
    }

    public function supports(string $scannerKey, ?string $scanModule = null): bool
    {
        return (bool) config('scanforge.scanner.mock_worker_enabled', true);
    }
}
