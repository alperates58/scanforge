<?php

namespace App\Scanners\Native;

use App\Models\RawArtifact;
use App\Models\ScanJob;
use App\Scanners\Contracts\ScannerInterface;
use App\Services\ArtifactManifestService;
use App\Services\FindingNormalizationService;
use App\Services\ScanJobLifecycleService;
use App\Services\ScanProgressService;
use App\Support\ScanJobStatuses;
use Illuminate\Support\Carbon;
use Throwable;

abstract class AbstractNativeScanner implements ScannerInterface
{
    public function __construct(
        protected readonly ScanJobLifecycleService $scanJobLifecycleService,
        protected readonly ScanProgressService $scanProgressService,
        protected readonly FindingNormalizationService $findingNormalizationService,
        protected readonly ArtifactManifestService $artifactManifestService,
    ) {
    }

    abstract protected function performChecks(ScanJob $scanJob): array;

    abstract public function scannerKey(): string;

    public function execute(ScanJob $scanJob): array
    {
        $scanJob = $scanJob->fresh(['scan.requestedBy', 'website', 'scanPlanItem']);

        if (in_array($scanJob->status, [ScanJobStatuses::COMPLETED, ScanJobStatuses::CANCELLED, ScanJobStatuses::SKIPPED], true)) {
            return ['skipped' => true, 'reason' => 'already_terminal'];
        }

        $validation = $this->validate($scanJob);

        if (! $validation['valid']) {
            $this->fail($scanJob, 'Native scanner validation rejected scan job.', ['errors' => $validation['errors']]);
            return ['failed' => true, 'errors' => $validation['errors']];
        }

        if ($this->isCancellationRequested($scanJob)) {
            $this->cancelJob($scanJob, 'Scan cancelled before execution started.');
            return ['cancelled' => true];
        }

        $startedAt = Carbon::now();
        $scanJob = $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::RUNNING, 'Native adapter starting scan job.', [
            'attempt_count' => (int) $scanJob->attempt_count + 1,
            'started_at' => $scanJob->started_at ?? $startedAt,
            'progress' => 10,
            'progress_percent' => 10,
            'last_heartbeat_at' => $startedAt,
        ], [
            'scanner_key' => $this->scannerKey(),
            'scan_module' => $scanJob->scan_module,
        ]);

        try {
            $results = $this->performChecks($scanJob);
            
            $payload = [
                'scanner_key' => $this->scannerKey(),
                'scan_job_id' => $scanJob->id,
                'results' => $results,
            ];
            $jsonl = json_encode($payload, JSON_UNESCAPED_SLASHES);

            $artifact = RawArtifact::query()->create([
                'scan_id' => $scanJob->scan_id,
                'scan_job_id' => $scanJob->id,
                'tool_name' => $this->scannerKey(),
                'scanner_key' => $this->scannerKey(),
                'artifact_type' => 'native_json',
                'json_payload' => $payload,
                'content' => $payload,
                'sha256' => hash('sha256', $jsonl),
            ]);

            $this->artifactManifestService->record($artifact, $jsonl, 'application/json', false, 'scan_raw_default', [
                'scanner_key' => $this->scannerKey(),
                'scan_job_id' => $scanJob->id,
            ]);

            $findingCount = 0;
            foreach ($results as $findingPayload) {
                $finding = $this->findingNormalizationService->persistNativeScannerFinding($scanJob, $artifact, $findingPayload);
                if ($finding) {
                    $findingCount++;
                }
            }

            $completedAt = Carbon::now();
            $resultSummary = [
                'scanner_key' => $this->scannerKey(),
                'findings_count' => $findingCount,
                'raw_artifact_id' => $artifact->id,
                'duration_ms' => $scanJob->started_at ? (int) round($scanJob->started_at->diffInMilliseconds($completedAt)) : 0,
            ];

            $this->scanJobLifecycleService->transition($scanJob->fresh(), ScanJobStatuses::COMPLETED, 'Native adapter completed scan job.', [
                'completed_at' => $completedAt,
                'finished_at' => $completedAt,
                'duration_ms' => $resultSummary['duration_ms'],
                'progress' => 100,
                'progress_percent' => 100,
                'result_summary' => $resultSummary,
                'error_message' => null,
                'last_heartbeat_at' => $completedAt,
            ]);

            $this->scanProgressService->refresh($scanJob->scan);

            return $resultSummary;
        } catch (Throwable $throwable) {
            $this->fail($scanJob->fresh(), 'Native adapter failed scan job.', [
                'exception' => $throwable::class,
                'message' => $throwable->getMessage(),
            ]);

            return ['failed' => true, 'error' => $throwable->getMessage()];
        }
    }

    public function cancel(ScanJob $scanJob): void
    {
        $scanJob->forceFill([
            'cancel_requested_at' => Carbon::now(),
            'cancellation_token' => $scanJob->cancellation_token ?: (string) str()->uuid(),
        ])->save();
    }

    public function validate(ScanJob $scanJob): array
    {
        $errors = [];
        $scanJob->loadMissing(['scan', 'website', 'scanPlanItem']);

        if (! $this->supports((string) $scanJob->scanner_key, $scanJob->scan_module)) {
            $errors[] = 'unsupported_scanner';
        }

        if (! $scanJob->website?->isVerified()) {
            $errors[] = 'domain_not_verified';
        }

        if ($scanJob->scan?->consent_accepted_at === null) {
            $errors[] = 'missing_authorization_consent';
        }

        if ($scanJob->scan_plan_item_id === null || $scanJob->scanPlanItem === null) {
            $errors[] = 'scan_plan_item_required';
        }

        return [
            'valid' => $errors === [],
            'errors' => array_values(array_unique($errors)),
        ];
    }

    public function supports(string $scannerKey, ?string $scanModule = null): bool
    {
        return $scannerKey === $this->scannerKey();
    }

    protected function fail(ScanJob $scanJob, string $reason, array $metadata = []): void
    {
        $now = Carbon::now();
        $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::FAILED, $reason, [
            'completed_at' => $now,
            'finished_at' => $now,
            'progress' => 100,
            'progress_percent' => 100,
            'error_message' => $metadata['message'] ?? $reason,
        ], $metadata);
        $this->scanProgressService->refresh($scanJob->scan);
    }

    protected function cancelJob(ScanJob $scanJob, string $reason, array $metadata = []): void
    {
        $now = Carbon::now();
        $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::CANCELLED, $reason, [
            'completed_at' => $now,
            'finished_at' => $now,
            'progress' => $scanJob->progress_percent,
            'progress_percent' => $scanJob->progress_percent,
        ], $metadata);
        $this->scanProgressService->refresh($scanJob->scan);
    }

    protected function isCancellationRequested(ScanJob $scanJob): bool
    {
        return $scanJob->cancel_requested_at !== null
            || $scanJob->status === ScanJobStatuses::CANCELLED
            || $scanJob->scan?->status === 'cancelled';
    }
}
