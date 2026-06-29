<?php

namespace App\Services;

use App\Events\ScanCancelled;
use App\Events\ScanCompleted;
use App\Events\ScanFailed;
use App\Models\Scan;
use App\Models\ScanJob;
use App\Support\ScanJobStatuses;
use App\Support\ScanStatuses;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Throwable;

class ScanProgressService
{
    public function __construct(private readonly AuditLogService $auditLogService)
    {
    }

    public function refresh(Scan $scan): Scan
    {
        $scan = $scan->fresh(['requestedBy']);
        $oldStatus = $scan->status;
        $total = ScanJob::query()->where('scan_id', $scan->id)->count();
        $completed = ScanJob::query()->where('scan_id', $scan->id)->where('status', ScanJobStatuses::COMPLETED)->count();
        $failed = ScanJob::query()->where('scan_id', $scan->id)->where('status', ScanJobStatuses::FAILED)->count();
        $timeout = ScanJob::query()->where('scan_id', $scan->id)->where('status', ScanJobStatuses::TIMEOUT)->count();
        $cancelled = ScanJob::query()->where('scan_id', $scan->id)->where('status', ScanJobStatuses::CANCELLED)->count();
        $skipped = ScanJob::query()->where('scan_id', $scan->id)->where('status', ScanJobStatuses::SKIPPED)->count();
        $running = ScanJob::query()->where('scan_id', $scan->id)->whereIn('status', [ScanJobStatuses::STARTING, ScanJobStatuses::RUNNING])->count();
        $averageProgress = (int) round((float) (ScanJob::query()->where('scan_id', $scan->id)->avg('progress_percent') ?? 0));
        $terminal = $completed + $failed + $timeout + $cancelled + $skipped;
        $newStatus = $scan->status;
        $completedAt = $scan->completed_at;
        $cancelledAt = $scan->cancelled_at;
        $finishedAt = $scan->finished_at;
        $durationMs = $scan->duration_ms;

        if ($total > 0 && $terminal >= $total) {
            if ($cancelled > 0) {
                $newStatus = ScanStatuses::CANCELLED;
                $cancelledAt ??= Carbon::now();
            } elseif ($timeout > 0) {
                $newStatus = ScanStatuses::TIMEOUT;
            } elseif ($failed > 0) {
                $newStatus = ScanStatuses::FAILED;
            } else {
                $newStatus = ScanStatuses::COMPLETED;
            }

            $completedAt ??= Carbon::now();
            $finishedAt ??= $completedAt;
            $averageProgress = 100;
        } elseif ($running > 0) {
            $newStatus = ScanStatuses::RUNNING;
        } elseif (! in_array($scan->status, [ScanStatuses::CANCELLED, ScanStatuses::FAILED, ScanStatuses::TIMEOUT, ScanStatuses::COMPLETED], true)) {
            $newStatus = ScanStatuses::QUEUED;
        }

        if ($scan->started_at && $completedAt && $durationMs === null) {
            $durationMs = (int) round($scan->started_at->diffInMilliseconds($completedAt));
        }

        $scan->forceFill([
            'status' => $newStatus,
            'progress_percent' => min(100, max(0, $averageProgress)),
            'total_jobs' => $total,
            'completed_jobs' => $completed,
            'failed_jobs' => $failed + $timeout,
            'skipped_jobs' => $skipped,
            'completed_at' => $completedAt,
            'finished_at' => $finishedAt,
            'cancelled_at' => $cancelledAt,
            'duration_ms' => $durationMs,
        ])->save();

        if ($oldStatus !== $newStatus && in_array($newStatus, [ScanStatuses::COMPLETED, ScanStatuses::FAILED, ScanStatuses::TIMEOUT, ScanStatuses::CANCELLED], true)) {
            $this->dispatchTerminalEvent($scan->fresh(), $newStatus);
            $this->releaseLock($scan->fresh());
        }

        return $scan->fresh();
    }

    private function dispatchTerminalEvent(Scan $scan, string $status): void
    {
        $action = match ($status) {
            ScanStatuses::COMPLETED => 'scan.completed',
            ScanStatuses::CANCELLED => 'scan.cancelled',
            default => 'scan.failed',
        };

        $this->auditLogService->record(
            $action,
            $scan->requestedBy,
            $scan->workspace_id,
            'scan',
            $scan->id,
            null,
            [
                'website_id' => $scan->website_id,
                'status' => $status,
                'total_jobs' => $scan->total_jobs,
                'completed_jobs' => $scan->completed_jobs,
                'failed_jobs' => $scan->failed_jobs,
            ],
        );

        match ($status) {
            ScanStatuses::COMPLETED => ScanCompleted::dispatch($scan),
            ScanStatuses::CANCELLED => ScanCancelled::dispatch($scan),
            default => ScanFailed::dispatch($scan),
        };
    }

    private function releaseLock(Scan $scan): void
    {
        $metadata = is_array($scan->metadata) ? $scan->metadata : [];
        $lockKey = $metadata['lock_key'] ?? null;
        $lockOwner = $metadata['lock_owner'] ?? null;

        if (! is_string($lockKey) || ! is_string($lockOwner)) {
            return;
        }

        try {
            Cache::restoreLock($lockKey, $lockOwner)->release();
        } catch (Throwable) {
            // Lock expiry is acceptable; it only protects scan start orchestration.
        }
    }
}
