<?php

namespace App\Services;

use App\Events\ScanStarted;
use App\Models\RawArtifact;
use App\Models\Scan;
use App\Models\ScanJob;
use App\Support\ScanJobStatuses;
use App\Support\ScanStatuses;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Throwable;

class MockExecutorService
{
    public function __construct(
        private readonly WorkerRegistryService $workerRegistryService,
        private readonly ScanJobLifecycleService $scanJobLifecycleService,
        private readonly ScanJobLogService $scanJobLogService,
        private readonly ScanProgressService $scanProgressService,
        private readonly AuditLogService $auditLogService,
    ) {
    }

    public function execute(int $scanJobId): void
    {
        $scanJob = ScanJob::query()->with('scan.requestedBy')->findOrFail($scanJobId);

        if (in_array($scanJob->status, [ScanJobStatuses::COMPLETED, ScanJobStatuses::CANCELLED], true)) {
            return;
        }

        $worker = $this->workerRegistryService->heartbeat($scanJob);

        if ($this->isCancellationRequested($scanJob)) {
            $this->cancel($scanJob, 'Scan job cancelled before mock execution started.');

            return;
        }

        try {
            $now = Carbon::now();
            $attempt = (int) $scanJob->attempt_count + 1;
            $scanJob = $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::STARTING, 'Mock executor accepted scan job.', [
                'worker_id' => $worker->worker_id,
                'attempt_count' => $attempt,
                'attempts' => $attempt,
                'started_at' => $scanJob->started_at ?? $now,
                'progress' => 5,
                'progress_percent' => 5,
                'last_heartbeat_at' => $now,
            ], [
                'worker_id' => $worker->worker_id,
                'mock_only' => true,
            ]);

            $this->markScanStarted($scanJob->scan);

            if ($this->isCancellationRequested($scanJob->fresh())) {
                $this->cancel($scanJob->fresh(), 'Scan job cancelled during mock start.');

                return;
            }

            $scanJob = $this->scanJobLifecycleService->transition($scanJob->fresh(), ScanJobStatuses::RUNNING, 'Mock executor running scanner contract.', [
                'progress' => 10,
                'progress_percent' => 10,
                'last_heartbeat_at' => Carbon::now(),
            ], [
                'scanner_key' => $scanJob->scanner_key,
                'scan_module' => $scanJob->scan_module,
            ]);

            foreach ((array) config('scanforge.orchestration.mock_progress_steps', [10, 35, 65, 100]) as $progress) {
                $scanJob = $scanJob->fresh();

                if ($this->isCancellationRequested($scanJob)) {
                    $this->cancel($scanJob, 'Scan job cancelled during mock progress.');

                    return;
                }

                $scanJob->forceFill([
                    'progress' => (int) $progress,
                    'progress_percent' => (int) $progress,
                    'request_count' => min((int) ($scanJob->max_requests ?? 5), max(1, (int) round(((int) $progress / 100) * 5))),
                    'last_heartbeat_at' => Carbon::now(),
                ])->save();

                $this->scanJobLogService->record($scanJob->fresh(), 'info', 'Mock executor progress update.', [
                    'progress_percent' => (int) $progress,
                ]);

                $this->workerRegistryService->heartbeat($scanJob->fresh());
            }

            $completedAt = Carbon::now();
            $scanJob = $scanJob->fresh();
            $resultSummary = [
                'mock' => true,
                'scanner_key' => $scanJob->scanner_key,
                'scan_module' => $scanJob->scan_module,
                'template_group' => $scanJob->template_group,
                'findings' => [
                    'critical' => 0,
                    'high' => 0,
                    'medium' => 0,
                    'low' => 0,
                    'info' => 1,
                ],
                'external_tools_executed' => [],
                'network_scanning_enabled' => false,
            ];

            $this->writeMockArtifact($scanJob, $resultSummary);

            $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::COMPLETED, 'Mock executor completed scan job.', [
                'completed_at' => $completedAt,
                'finished_at' => $completedAt,
                'duration_ms' => $scanJob->started_at ? (int) round($scanJob->started_at->diffInMilliseconds($completedAt)) : 0,
                'progress' => 100,
                'progress_percent' => 100,
                'request_count' => max(1, (int) $scanJob->request_count),
                'result_summary' => $resultSummary,
                'error_message' => null,
                'last_heartbeat_at' => $completedAt,
            ]);

            $this->workerRegistryService->heartbeat($scanJob->fresh());
            $this->scanProgressService->refresh($scanJob->scan);
        } catch (Throwable $throwable) {
            if (DB::transactionLevel() > 0) {
                throw $throwable;
            }

            $scanJob = $scanJob->fresh();
            $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::FAILED, 'Mock executor failed scan job.', [
                'completed_at' => Carbon::now(),
                'finished_at' => Carbon::now(),
                'error_message' => $throwable->getMessage(),
            ], [
                'exception' => $throwable::class,
            ]);

            $this->scanProgressService->refresh($scanJob->scan);
        }
    }

    private function markScanStarted(Scan $scan): void
    {
        $scan = $scan->fresh(['requestedBy']);

        if ($scan->started_at !== null) {
            return;
        }

        $scan->forceFill([
            'status' => ScanStatuses::RUNNING,
            'started_at' => Carbon::now(),
        ])->save();

        $this->auditLogService->record(
            'scan.started',
            $scan->requestedBy,
            $scan->workspace_id,
            'scan',
            $scan->id,
            null,
            [
                'website_id' => $scan->website_id,
                'scan_plan_id' => $scan->scan_plan_id,
            ],
        );

        ScanStarted::dispatch($scan->fresh());
    }

    private function cancel(ScanJob $scanJob, string $reason): void
    {
        $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::CANCELLED, $reason, [
            'completed_at' => Carbon::now(),
            'finished_at' => Carbon::now(),
            'progress' => $scanJob->progress_percent,
        ]);

        $this->scanProgressService->refresh($scanJob->scan);
    }

    private function isCancellationRequested(ScanJob $scanJob): bool
    {
        return $scanJob->cancel_requested_at !== null
            || $scanJob->status === ScanJobStatuses::CANCELLED
            || $scanJob->scan?->status === ScanStatuses::CANCELLED;
    }

    /**
     * @param array<string, mixed> $resultSummary
     */
    private function writeMockArtifact(ScanJob $scanJob, array $resultSummary): void
    {
        $content = [
            'type' => 'mock_result',
            'scan_job_id' => $scanJob->id,
            'scanner_key' => $scanJob->scanner_key,
            'result_summary' => $resultSummary,
        ];
        $encoded = json_encode($content, JSON_THROW_ON_ERROR);

        RawArtifact::query()->create([
            'scan_id' => $scanJob->scan_id,
            'scan_job_id' => $scanJob->id,
            'tool_name' => $scanJob->scanner_key ?? 'mock',
            'scanner_key' => $scanJob->scanner_key ?? 'mock',
            'artifact_type' => 'mock_result',
            'json_payload' => $content,
            'content' => $content,
            'sha256' => hash('sha256', $encoded),
        ]);
    }
}
