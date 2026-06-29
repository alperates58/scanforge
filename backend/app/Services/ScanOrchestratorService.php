<?php

namespace App\Services;

use App\Events\JobQueued;
use App\Events\ScanQueued;
use App\Exceptions\ScanOrchestrationException;
use App\Jobs\ExecuteScanJob;
use App\Models\RawArtifact;
use App\Models\Scan;
use App\Models\ScanJob;
use App\Models\ScanPlan;
use App\Models\ScanPlanItem;
use App\Models\User;
use App\Models\Website;
use App\Models\Workspace;
use App\Support\QueueNames;
use App\Support\SafetyModes;
use App\Support\ScanJobStatuses;
use App\Support\ScanStatuses;
use App\Support\ScanTypes;
use Illuminate\Cache\Lock;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Throwable;

class ScanOrchestratorService
{
    public function __construct(
        private readonly TargetUrlGuard $targetUrlGuard,
        private readonly ScanSafetyGate $scanSafetyGate,
        private readonly AuditLogService $auditLogService,
        private readonly ScanJobLifecycleService $scanJobLifecycleService,
        private readonly ScanProgressService $scanProgressService,
    ) {
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function start(Workspace $workspace, Website $website, User $user, array $payload, ?string $ipAddress = null): array
    {
        $this->targetUrlGuard->assertPublicHost((string) $website->host);

        $scanType = (string) $payload['scan_type'];
        $safetyMode = (string) ($payload['safety_mode'] ?? $this->defaultSafetyMode($scanType));
        $credentialId = isset($payload['credential_id']) ? (int) $payload['credential_id'] : null;
        $scanPlan = $this->resolveScanPlan($website, $payload['scan_plan_id'] ?? null);
        $lockKey = $this->lockKey($website);
        $lock = Cache::lock($lockKey, (int) config('scanforge.orchestration.lock_ttl_seconds', 900));

        if (! $lock->get()) {
            $this->auditLogService->record(
                'scan.blocked',
                $user,
                $workspace->id,
                'website',
                $website->id,
                $ipAddress,
                [
                    'error_code' => 'scan_lock_active',
                    'lock_key' => $lockKey,
                ],
            );

            throw new ScanOrchestrationException('scan_lock_active', 429, ['scan_lock_active'], 'A scan is already being orchestrated for this website.');
        }

        try {
            $scan = DB::transaction(function () use ($workspace, $website, $user, $payload, $ipAddress, $scanType, $safetyMode, $credentialId, $scanPlan, $lockKey, $lock): Scan {
                $lockedWorkspace = Workspace::query()->whereKey($workspace->id)->lockForUpdate()->firstOrFail();
                $lockedWebsite = Website::query()->where('workspace_id', $lockedWorkspace->id)->whereKey($website->id)->firstOrFail();
                $lockedPlan = $scanPlan ? ScanPlan::query()->where('workspace_id', $lockedWorkspace->id)->where('website_id', $lockedWebsite->id)->whereKey($scanPlan->id)->first() : null;
                $gate = $this->scanSafetyGate->evaluateStart(
                    $lockedWorkspace,
                    $lockedWebsite,
                    $lockedPlan,
                    $scanType,
                    $safetyMode,
                    (bool) ($payload['consent_accepted'] ?? false),
                    $credentialId,
                );

                if (! $gate['allowed']) {
                    $this->auditLogService->record(
                        'scan.blocked',
                        $user,
                        $lockedWorkspace->id,
                        'website',
                        $lockedWebsite->id,
                        $ipAddress,
                        [
                            'scan_type' => $scanType,
                            'safety_mode' => $safetyMode,
                            'error_code' => $gate['error_code'],
                            'reasons' => $gate['reasons'],
                        ],
                    );

                    throw new ScanOrchestrationException($gate['error_code'], $gate['status_code'], $gate['reasons']);
                }

                $itemCount = ScanPlanItem::query()->where('scan_plan_id', $lockedPlan->id)->count();

                if ($itemCount === 0) {
                    throw new ScanOrchestrationException('scan_plan_empty', 409, ['scan_plan_empty'], 'The selected scan plan has no executable items.');
                }

                $now = Carbon::now();
                $requestBudget = (int) ScanPlanItem::query()->where('scan_plan_id', $lockedPlan->id)->sum('estimated_requests');
                $timeoutSeconds = max(
                    (int) config('scanforge.scanner.default_timeout_seconds', 900),
                    (int) ScanPlanItem::query()->where('scan_plan_id', $lockedPlan->id)->sum('estimated_duration_seconds'),
                );
                $scan = Scan::query()->create([
                    'workspace_id' => $lockedWorkspace->id,
                    'website_id' => $lockedWebsite->id,
                    'scan_plan_id' => $lockedPlan->id,
                    'scan_type' => $scanType,
                    'status' => ScanStatuses::QUEUED,
                    'safe_mode' => $safetyMode === SafetyModes::SAFE,
                    'safety_mode' => $safetyMode,
                    'consent_accepted_at' => $now,
                    'requested_by_user_id' => $user->id,
                    'request_options' => [
                        'phase' => 'phase05',
                        'mock_only' => true,
                        'options' => $payload['options'] ?? [],
                    ],
                    'request_budget' => $requestBudget,
                    'timeout_seconds' => $timeoutSeconds,
                    'progress_percent' => 0,
                    'total_jobs' => $itemCount,
                    'metadata' => [
                        'phase' => 'phase05',
                        'mock_only' => true,
                        'lock_key' => $lockKey,
                        'lock_owner' => $lock->owner(),
                        'credential_id' => $credentialId,
                    ],
                ]);

                $lockedWorkspace->increment('scans_used_this_month');
                $this->createScanJobs($scan, $lockedPlan, $lockedWebsite);

                $this->auditLogService->record(
                    'scan.queued',
                    $user,
                    $lockedWorkspace->id,
                    'scan',
                    $scan->id,
                    $ipAddress,
                    [
                        'website_id' => $lockedWebsite->id,
                        'scan_plan_id' => $lockedPlan->id,
                        'scan_type' => $scanType,
                        'safety_mode' => $safetyMode,
                        'total_jobs' => $itemCount,
                        'mock_only' => true,
                    ],
                );

                return $scan->fresh();
            });
        } catch (Throwable $throwable) {
            $this->releaseLock($lock);

            throw $throwable;
        }

        $this->recordQueuedJobLifecycle($scan);
        ScanQueued::dispatch($scan->fresh());
        $this->dispatchScanJobs($scan);

        return $this->scanData($scan->fresh(), includeJobs: true);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function list(Workspace $workspace, Website $website): array
    {
        return Scan::query()
            ->where('workspace_id', $workspace->id)
            ->where('website_id', $website->id)
            ->latest()
            ->limit(25)
            ->get()
            ->map(fn (Scan $scan): array => $this->scanData($scan, includeJobs: false))
            ->values()
            ->all();
    }

    /**
     * @return array<string, mixed>
     */
    public function detail(Workspace $workspace, Website $website, int $scanId): array
    {
        $scan = $this->findScan($workspace, $website, $scanId);

        return $this->scanData($scan, includeJobs: true);
    }

    /**
     * @return array<string, mixed>
     */
    public function jobs(Workspace $workspace, Website $website, int $scanId): array
    {
        $scan = $this->findScan($workspace, $website, $scanId);

        return [
            'scan_id' => $scan->id,
            'jobs' => $this->jobList($scan),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function cancel(Workspace $workspace, Website $website, User $user, int $scanId, ?string $ipAddress = null): array
    {
        $scan = $this->findScan($workspace, $website, $scanId);
        $now = Carbon::now();

        ScanJob::query()
            ->where('scan_id', $scan->id)
            ->whereIn('status', [ScanJobStatuses::PENDING, ScanJobStatuses::QUEUED, ScanJobStatuses::STARTING, ScanJobStatuses::RUNNING])
            ->orderBy('id')
            ->chunkById(250, function ($jobs) use ($now): void {
                foreach ($jobs as $scanJob) {
                    $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::CANCELLED, 'Scan cancellation requested.', [
                        'cancel_requested_at' => $now,
                        'completed_at' => $now,
                        'finished_at' => $now,
                        'cancellation_token' => $scanJob->cancellation_token ?: (string) str()->uuid(),
                    ]);
                }
            });

        $this->auditLogService->record(
            'scan.cancel_requested',
            $user,
            $workspace->id,
            'scan',
            $scan->id,
            $ipAddress,
            [
                'website_id' => $website->id,
            ],
        );

        $scan = $this->scanProgressService->refresh($scan);

        if ($scan->status !== ScanStatuses::CANCELLED) {
            $scan->forceFill([
                'status' => ScanStatuses::CANCELLED,
                'cancelled_at' => $now,
                'completed_at' => $now,
                'finished_at' => $now,
            ])->save();
            $scan = $this->scanProgressService->refresh($scan);
        }

        return $this->scanData($scan->fresh(), includeJobs: true);
    }

    /**
     * @return array<string, mixed>
     */
    public function retryFailed(Workspace $workspace, Website $website, User $user, int $scanId, ?string $ipAddress = null): array
    {
        $scan = $this->findScan($workspace, $website, $scanId);
        $lockKey = $this->lockKey($website);
        $lock = Cache::lock($lockKey, (int) config('scanforge.orchestration.lock_ttl_seconds', 900));

        if (! $lock->get()) {
            throw new ScanOrchestrationException('scan_lock_active', 429, ['scan_lock_active'], 'A scan is already being orchestrated for this website.');
        }

        try {
            $retried = [];

            ScanJob::query()
                ->where('scan_id', $scan->id)
                ->whereIn('status', [ScanJobStatuses::FAILED, ScanJobStatuses::TIMEOUT])
                ->whereColumn('attempt_count', '<', 'max_attempts')
                ->orderBy('id')
                ->chunkById(250, function ($jobs) use (&$retried): void {
                    foreach ($jobs as $scanJob) {
                        $retried[] = $this->scanJobLifecycleService->retryQueued($scanJob)->id;
                    }
                });

            if ($retried !== []) {
                $scan->forceFill([
                    'status' => ScanStatuses::QUEUED,
                    'completed_at' => null,
                    'finished_at' => null,
                    'cancelled_at' => null,
                    'metadata' => [
                        ...(is_array($scan->metadata) ? $scan->metadata : []),
                        'lock_key' => $lockKey,
                        'lock_owner' => $lock->owner(),
                    ],
                ])->save();

                $this->auditLogService->record(
                    'scan.retry_failed',
                    $user,
                    $workspace->id,
                    'scan',
                    $scan->id,
                    $ipAddress,
                    [
                        'retried_jobs' => count($retried),
                    ],
                );

                $this->dispatchSpecificJobs($retried);
            } else {
                $this->releaseLock($lock);
            }
        } catch (Throwable $throwable) {
            $this->releaseLock($lock);

            throw $throwable;
        }

        return $this->scanData($scan->fresh(), includeJobs: true);
    }

    /**
     * @return array<string, int|float|string|null>
     */
    public function workerMetrics(Workspace $workspace, ScanMetricsService $scanMetricsService): array
    {
        return $scanMetricsService->workspaceMetrics($workspace->id);
    }

    private function resolveScanPlan(Website $website, mixed $scanPlanId): ?ScanPlan
    {
        $query = ScanPlan::query()
            ->where('workspace_id', $website->workspace_id)
            ->where('website_id', $website->id)
            ->whereIn('status', ['ready', 'generated']);

        if ($scanPlanId !== null && $scanPlanId !== '') {
            return $query->whereKey((int) $scanPlanId)->first();
        }

        return $query->latest('generated_at')->first();
    }

    private function createScanJobs(Scan $scan, ScanPlan $scanPlan, Website $website): void
    {
        $now = Carbon::now();

        ScanPlanItem::query()
            ->where('scan_plan_id', $scanPlan->id)
            ->orderByDesc('priority')
            ->orderBy('id')
            ->chunkById(500, function ($items) use ($scan, $website, $now): void {
                $rows = [];

                foreach ($items as $item) {
                    $priority = (int) $item->priority;
                    $metadata = is_array($item->metadata) ? $item->metadata : [];
                    $rows[] = [
                        'workspace_id' => $scan->workspace_id,
                        'website_id' => $website->id,
                        'scan_id' => $scan->id,
                        'scan_plan_item_id' => $item->id,
                        'job_type' => 'mock_scan',
                        'scanner_key' => $item->scanner_key,
                        'scan_module' => $item->scan_module,
                        'template_group' => $item->template_group,
                        'status' => ScanJobStatuses::QUEUED,
                        'priority' => $priority,
                        'recommendation_score' => (int) $item->recommendation_score,
                        'safe_default' => (bool) ($metadata['safe_default'] ?? $item->safe_mode),
                        'progress' => 0,
                        'attempts' => 0,
                        'attempt_count' => 0,
                        'max_attempts' => $this->retryMaxAttempts((string) $item->scanner_key),
                        'timeout_seconds' => $this->jobTimeout($item),
                        'progress_percent' => 0,
                        'request_count' => 0,
                        'lock_key' => $this->lockKey($website),
                        'queue_name' => QueueNames::forPriority($priority),
                        'max_requests' => max(1, (int) ($item->estimated_requests ?: config('scanforge.orchestration.default_job_max_requests', 50))),
                        'max_runtime' => max(1, (int) ($item->estimated_duration_seconds ?: config('scanforge.orchestration.default_job_max_runtime', 300))),
                        'max_memory' => max(64, (int) ($item->estimated_memory_mb ?: config('scanforge.orchestration.default_job_max_memory', 256))),
                        'cancellation_token' => (string) str()->uuid(),
                        'logs' => json_encode(['Queued by Phase 05 mock orchestrator.']),
                        'created_at' => $now,
                        'updated_at' => $now,
                    ];
                }

                if ($rows !== []) {
                    DB::table('scan_jobs')->insert($rows);
                }
            });
    }

    private function recordQueuedJobLifecycle(Scan $scan): void
    {
        ScanJob::query()
            ->where('scan_id', $scan->id)
            ->orderBy('id')
            ->chunkById(500, function ($jobs): void {
                $now = Carbon::now();
                $timelineRows = [];
                $logRows = [];

                foreach ($jobs as $scanJob) {
                    $timelineRows[] = [
                        'scan_job_id' => $scanJob->id,
                        'scan_id' => $scanJob->scan_id,
                        'workspace_id' => $scanJob->workspace_id,
                        'from_status' => null,
                        'to_status' => ScanJobStatuses::QUEUED,
                        'reason' => 'Scan job queued from scan plan item.',
                        'metadata' => json_encode([
                            'queue_name' => $scanJob->queue_name,
                            'scanner_key' => $scanJob->scanner_key,
                        ]),
                        'occurred_at' => $now,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ];
                    $logRows[] = [
                        'scan_job_id' => $scanJob->id,
                        'scan_id' => $scanJob->scan_id,
                        'workspace_id' => $scanJob->workspace_id,
                        'timestamp' => $now,
                        'level' => 'info',
                        'message' => 'Scan job queued from scan plan item.',
                        'context' => json_encode([
                            'queue_name' => $scanJob->queue_name,
                            'scanner_key' => $scanJob->scanner_key,
                        ]),
                        'created_at' => $now,
                        'updated_at' => $now,
                    ];
                }

                if ($timelineRows !== []) {
                    DB::table('scan_job_timelines')->insert($timelineRows);
                    DB::table('scan_job_logs')->insert($logRows);
                }

                foreach ($jobs as $scanJob) {
                    JobQueued::dispatch($scanJob);
                }
            });
    }

    private function dispatchScanJobs(Scan $scan): void
    {
        ScanJob::query()
            ->where('scan_id', $scan->id)
            ->select(['id', 'queue_name'])
            ->orderBy('id')
            ->chunkById(250, function ($jobs) use ($scan): void {
                $batchJobs = $jobs
                    ->map(fn (ScanJob $scanJob): ExecuteScanJob => (new ExecuteScanJob($scanJob->id))->onQueue($scanJob->queue_name))
                    ->all();

                if ($batchJobs !== []) {
                    Bus::batch($batchJobs)
                        ->name('scan-'.$scan->id)
                        ->allowFailures()
                        ->dispatch();
                }
            });
    }

    /**
     * @param list<int> $scanJobIds
     */
    private function dispatchSpecificJobs(array $scanJobIds): void
    {
        ScanJob::query()
            ->whereIn('id', $scanJobIds)
            ->select(['id', 'queue_name'])
            ->orderBy('id')
            ->chunkById(250, function ($jobs): void {
                $batchJobs = $jobs
                    ->map(fn (ScanJob $scanJob): ExecuteScanJob => (new ExecuteScanJob($scanJob->id))->onQueue($scanJob->queue_name))
                    ->all();

                if ($batchJobs !== []) {
                    Bus::batch($batchJobs)
                        ->name('scan-retry')
                        ->allowFailures()
                        ->dispatch();
                }
            });
    }

    private function findScan(Workspace $workspace, Website $website, int $scanId): Scan
    {
        return Scan::query()
            ->where('workspace_id', $workspace->id)
            ->where('website_id', $website->id)
            ->whereKey($scanId)
            ->firstOrFail();
    }

    /**
     * @return array<string, mixed>
     */
    private function scanData(Scan $scan, bool $includeJobs): array
    {
        $scan->loadMissing('scanPlan');

        $data = [
            'id' => $scan->id,
            'workspace_id' => $scan->workspace_id,
            'website_id' => $scan->website_id,
            'scan_plan_id' => $scan->scan_plan_id,
            'status' => $scan->status,
            'scan_type' => $scan->scan_type,
            'safety_mode' => $scan->safety_mode,
            'request_budget' => $scan->request_budget,
            'timeout_seconds' => $scan->timeout_seconds,
            'progress_percent' => $scan->progress_percent,
            'total_jobs' => $scan->total_jobs,
            'completed_jobs' => $scan->completed_jobs,
            'failed_jobs' => $scan->failed_jobs,
            'skipped_jobs' => $scan->skipped_jobs,
            'started_at' => $scan->started_at?->toISOString(),
            'completed_at' => $scan->completed_at?->toISOString(),
            'cancelled_at' => $scan->cancelled_at?->toISOString(),
            'duration_ms' => $scan->duration_ms,
            'error_message' => $scan->error_message,
            'plan' => $scan->scanPlan ? [
                'id' => $scan->scanPlan->id,
                'status' => $scan->scanPlan->status,
                'coverage_prediction' => $scan->scanPlan->coverage_prediction,
                'estimated_requests' => $scan->scanPlan->estimated_requests,
            ] : null,
            'recent_findings' => [],
            'artifacts_count' => RawArtifact::query()->where('scan_id', $scan->id)->count(),
            'created_at' => $scan->created_at?->toISOString(),
        ];

        if ($includeJobs) {
            $data['jobs'] = $this->jobList($scan);
        }

        return $data;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function jobList(Scan $scan): array
    {
        return ScanJob::query()
            ->where('scan_id', $scan->id)
            ->with('scanPlanItem')
            ->orderByDesc('priority')
            ->orderBy('id')
            ->get()
            ->map(fn (ScanJob $scanJob): array => [
                'id' => $scanJob->id,
                'scan_plan_item_id' => $scanJob->scan_plan_item_id,
                'scanner_key' => $scanJob->scanner_key,
                'scan_module' => $scanJob->scan_module,
                'template_group' => $scanJob->template_group,
                'status' => $scanJob->status,
                'queue_name' => $scanJob->queue_name,
                'priority' => $scanJob->priority,
                'recommendation_score' => $scanJob->recommendation_score,
                'safe_default' => $scanJob->safe_default,
                'attempt_count' => $scanJob->attempt_count,
                'max_attempts' => $scanJob->max_attempts,
                'timeout_seconds' => $scanJob->timeout_seconds,
                'progress_percent' => $scanJob->progress_percent,
                'request_count' => $scanJob->request_count,
                'max_requests' => $scanJob->max_requests,
                'max_runtime' => $scanJob->max_runtime,
                'max_memory' => $scanJob->max_memory,
                'worker_id' => $scanJob->worker_id,
                'started_at' => $scanJob->started_at?->toISOString(),
                'completed_at' => $scanJob->completed_at?->toISOString(),
                'duration_ms' => $scanJob->duration_ms,
                'result_summary' => $scanJob->result_summary,
                'error_message' => $scanJob->error_message,
                'plan_item' => $scanJob->scanPlanItem ? [
                    'technology_key' => $scanJob->scanPlanItem->technology_key,
                    'reason' => $scanJob->scanPlanItem->reason,
                ] : null,
            ])
            ->values()
            ->all();
    }

    private function retryMaxAttempts(string $scannerKey): int
    {
        return (int) config("scanforge.retry.scanners.{$scannerKey}.max_attempts", config('scanforge.retry.default.max_attempts', 2));
    }

    private function jobTimeout(ScanPlanItem $item): int
    {
        return max(1, (int) ($item->estimated_duration_seconds ?: config('scanforge.orchestration.default_job_timeout_seconds', 300)));
    }

    private function defaultSafetyMode(string $scanType): string
    {
        return match ($scanType) {
            ScanTypes::PASSIVE => SafetyModes::SAFE,
            ScanTypes::DEEP => SafetyModes::DEEP,
            ScanTypes::AUTHENTICATED => SafetyModes::AUTHENTICATED,
            default => SafetyModes::STANDARD,
        };
    }

    private function lockKey(Website $website): string
    {
        return 'scanforge:scan:'.$website->id;
    }

    private function releaseLock(Lock $lock): void
    {
        try {
            $lock->release();
        } catch (Throwable) {
            //
        }
    }
}
