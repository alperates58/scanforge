<?php

namespace App\Services;

use App\Models\ScanJob;
use App\Scanners\ScannerRegistry;
use App\Support\ScanJobStatuses;
use Illuminate\Support\Carbon;
use Throwable;

class ScannerExecutorService
{
    public function __construct(
        private readonly ScannerRegistry $scannerRegistry,
        private readonly WorkerRegistryService $workerRegistryService,
        private readonly ScanJobLifecycleService $scanJobLifecycleService,
        private readonly ScanProgressService $scanProgressService,
    ) {
    }

    public function execute(int $scanJobId): void
    {
        $scanJob = ScanJob::query()->with(['scan', 'website', 'scanPlanItem'])->findOrFail($scanJobId);

        if (in_array($scanJob->status, ScanJobStatuses::terminal(), true)) {
            return;
        }

        $scannerKey = (string) ($scanJob->scanner_key ?: 'mock');

        if (! $this->workerRegistryService->supports($scannerKey)) {
            $now = Carbon::now();
            $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::SKIPPED, 'No worker capability is available for scanner.', [
                'completed_at' => $now,
                'finished_at' => $now,
                'progress' => 100,
                'progress_percent' => 100,
                'error_message' => 'worker_capability_missing',
            ], [
                'scanner_key' => $scannerKey,
            ]);
            $this->scanProgressService->refresh($scanJob->scan);

            return;
        }

        try {
            $scanner = $this->scannerRegistry->resolve($scannerKey, $scanJob->scan_module);
            $scanner->execute($scanJob);
        } catch (Throwable $throwable) {
            $now = Carbon::now();
            $this->scanJobLifecycleService->transition($scanJob->fresh(), ScanJobStatuses::FAILED, 'Scanner executor failed scan job.', [
                'completed_at' => $now,
                'finished_at' => $now,
                'progress' => 100,
                'progress_percent' => 100,
                'error_message' => $throwable->getMessage(),
            ], [
                'scanner_key' => $scannerKey,
                'exception' => $throwable::class,
            ]);
            $this->scanProgressService->refresh($scanJob->scan);
        }
    }
}
