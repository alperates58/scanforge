<?php

namespace App\Services;

use App\Events\WorkerHeartbeat;
use App\Events\WorkerRegistered;
use App\Models\ScanJob;
use App\Models\Worker;
use App\Support\ScanJobStatuses;
use Illuminate\Support\Carbon;

class WorkerRegistryService
{
    public function workerId(): string
    {
        $configured = config('scanforge.scanner.worker_id');

        if (is_string($configured) && trim($configured) !== '') {
            return trim($configured);
        }

        return gethostname() ?: 'scanforge-worker';
    }

    public function heartbeat(?ScanJob $scanJob = null): Worker
    {
        $workerId = $this->workerId();
        $existing = Worker::query()->where('worker_id', $workerId)->first();
        $registeredScanners = array_keys((array) config('scanners.adapters', []));
        $capabilityScanners = collect(config('scanner_capabilities', []))
            ->pluck('scanner_key')
            ->filter()
            ->unique()
            ->values()
            ->all();
        $supportedScanners = collect([...$registeredScanners, ...$capabilityScanners, 'mock'])
            ->filter(fn (string $scannerKey): bool => $this->supports($scannerKey))
            ->unique()
            ->values()
            ->all();

        $worker = Worker::query()->updateOrCreate(
            ['worker_id' => $workerId],
            [
                'hostname' => gethostname() ?: $workerId,
                'version' => (string) config('scanforge.version'),
                'supported_scanners' => $supportedScanners,
                'status' => 'online',
                'current_jobs' => ScanJob::query()
                    ->where('worker_id', $workerId)
                    ->whereIn('status', [ScanJobStatuses::STARTING, ScanJobStatuses::RUNNING])
                    ->count(),
                'max_jobs' => (int) config('scanforge.scanner.worker_max_jobs', 1),
                'last_heartbeat' => Carbon::now(),
                'metadata' => [
                    'mock_fallback_enabled' => (bool) config('scanners.fallback_to_mock', true),
                    'last_scan_job_id' => $scanJob?->id,
                ],
            ],
        );

        if ($existing === null) {
            WorkerRegistered::dispatch($worker);
        }

        WorkerHeartbeat::dispatch($worker);

        return $worker;
    }

    public function supports(string $scannerKey): bool
    {
        if ((bool) config('scanners.fallback_to_mock', true)) {
            return true;
        }

        return array_key_exists($scannerKey, (array) config('scanners.adapters', []));
    }
}
