<?php

namespace App\Services;

use App\Models\ScanJob;
use App\Models\Worker;
use App\Support\ScanJobStatuses;

class ScanMetricsService
{
    /**
     * @return array<string, int|float>
     */
    public function workspaceMetrics(int $workspaceId): array
    {
        $activeJobs = ScanJob::query()
            ->where('workspace_id', $workspaceId)
            ->whereIn('status', [ScanJobStatuses::STARTING, ScanJobStatuses::RUNNING])
            ->count();

        $queuedJobs = ScanJob::query()
            ->where('workspace_id', $workspaceId)
            ->whereIn('status', [ScanJobStatuses::PENDING, ScanJobStatuses::QUEUED])
            ->count();

        $failedJobs = ScanJob::query()
            ->where('workspace_id', $workspaceId)
            ->whereIn('status', [ScanJobStatuses::FAILED, ScanJobStatuses::TIMEOUT])
            ->count();

        return [
            'active_workers' => Worker::query()->where('status', 'online')->count(),
            'active_jobs' => $activeJobs,
            'queued_jobs' => $queuedJobs,
            'failed_jobs' => $failedJobs,
            'avg_job_time' => round((float) (ScanJob::query()
                ->where('workspace_id', $workspaceId)
                ->whereNotNull('duration_ms')
                ->avg('duration_ms') ?? 0), 1),
        ];
    }
}
