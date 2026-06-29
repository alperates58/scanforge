<?php

namespace App\Services;

use App\Events\JobCancelled;
use App\Events\JobCompleted;
use App\Events\JobQueued;
use App\Events\JobRetried;
use App\Events\JobStarted;
use App\Events\JobTimedOut;
use App\Events\ScanJobCompleted;
use App\Events\ScanJobFailed;
use App\Events\ScanJobStarted;
use App\Models\ScanJob;
use App\Models\ScanJobTimeline;
use App\Support\ScanJobStatuses;
use Illuminate\Support\Carbon;

class ScanJobLifecycleService
{
    public function __construct(private readonly ScanJobLogService $scanJobLogService)
    {
    }

    /**
     * @param array<string, mixed> $attributes
     * @param array<string, mixed> $metadata
     */
    public function transition(ScanJob $scanJob, string $toStatus, string $reason, array $attributes = [], array $metadata = []): ScanJob
    {
        $fromStatus = $scanJob->status;
        $now = Carbon::now();

        $scanJob->forceFill([
            ...$attributes,
            'status' => $toStatus,
            'updated_at' => $now,
        ])->save();

        ScanJobTimeline::query()->create([
            'scan_job_id' => $scanJob->id,
            'scan_id' => $scanJob->scan_id,
            'workspace_id' => $scanJob->workspace_id,
            'from_status' => $fromStatus,
            'to_status' => $toStatus,
            'reason' => $reason,
            'metadata' => $metadata,
            'occurred_at' => $now,
        ]);

        $this->scanJobLogService->record($scanJob->fresh(), $this->levelForStatus($toStatus), $reason, [
            'from_status' => $fromStatus,
            'to_status' => $toStatus,
            ...$metadata,
        ]);

        $this->dispatchStatusEvent($scanJob->fresh(), $toStatus);

        return $scanJob->fresh();
    }

    public function retryQueued(ScanJob $scanJob): ScanJob
    {
        $scanJob = $this->transition($scanJob, ScanJobStatuses::QUEUED, 'Scan job requeued for retry.', [
            'progress' => 0,
            'progress_percent' => 0,
            'error_message' => null,
            'cancel_requested_at' => null,
            'cancellation_token' => (string) str()->uuid(),
        ]);

        JobRetried::dispatch($scanJob);

        return $scanJob;
    }

    private function levelForStatus(string $status): string
    {
        return match ($status) {
            ScanJobStatuses::FAILED, ScanJobStatuses::TIMEOUT => 'error',
            ScanJobStatuses::CANCELLED => 'warning',
            default => 'info',
        };
    }

    private function dispatchStatusEvent(ScanJob $scanJob, string $status): void
    {
        match ($status) {
            ScanJobStatuses::QUEUED => JobQueued::dispatch($scanJob),
            ScanJobStatuses::STARTING => $this->dispatchStarted($scanJob),
            ScanJobStatuses::COMPLETED => $this->dispatchCompleted($scanJob),
            ScanJobStatuses::FAILED => $this->dispatchFailed($scanJob),
            ScanJobStatuses::TIMEOUT => $this->dispatchTimedOut($scanJob),
            ScanJobStatuses::CANCELLED => JobCancelled::dispatch($scanJob),
            default => null,
        };
    }

    private function dispatchStarted(ScanJob $scanJob): void
    {
        JobStarted::dispatch($scanJob);
        ScanJobStarted::dispatch($scanJob);
    }

    private function dispatchCompleted(ScanJob $scanJob): void
    {
        JobCompleted::dispatch($scanJob);
        ScanJobCompleted::dispatch($scanJob);
    }

    private function dispatchFailed(ScanJob $scanJob): void
    {
        ScanJobFailed::dispatch($scanJob);
    }

    private function dispatchTimedOut(ScanJob $scanJob): void
    {
        JobTimedOut::dispatch($scanJob);
        ScanJobFailed::dispatch($scanJob);
    }
}
