<?php

namespace App\Scanners\Nuclei;

use App\Events\ScanStarted;
use App\Models\RawArtifact;
use App\Models\Scan;
use App\Models\ScanJob;
use App\Scanners\Contracts\ScannerInterface;
use App\Scanners\Contracts\ScannerProcessRunnerInterface;
use App\Services\ArtifactManifestService;
use App\Services\AuditLogService;
use App\Services\FindingDeltaService;
use App\Services\NucleiFindingNormalizer;
use App\Services\ScannerRunMetricService;
use App\Services\ScannerSandboxService;
use App\Services\ScannerTemplatePolicyService;
use App\Services\ScannerVersionService;
use App\Services\ScanJobLifecycleService;
use App\Services\ScanJobLogService;
use App\Services\ScanProgressService;
use App\Services\TargetUrlGuard;
use App\Services\WorkerRegistryService;
use App\Support\ScanJobStatuses;
use App\Support\ScanStatuses;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\File;
use Throwable;

class NucleiScanner implements ScannerInterface
{
    public function __construct(
        private readonly TargetUrlGuard $targetUrlGuard,
        private readonly WorkerRegistryService $workerRegistryService,
        private readonly ScanJobLifecycleService $scanJobLifecycleService,
        private readonly ScanJobLogService $scanJobLogService,
        private readonly ScanProgressService $scanProgressService,
        private readonly AuditLogService $auditLogService,
        private readonly ScannerSandboxService $scannerSandboxService,
        private readonly ScannerTemplatePolicyService $scannerTemplatePolicyService,
        private readonly ScannerProcessRunnerInterface $scannerProcessRunner,
        private readonly NucleiFindingNormalizer $nucleiFindingNormalizer,
        private readonly ArtifactManifestService $artifactManifestService,
        private readonly ScannerRunMetricService $scannerRunMetricService,
        private readonly ScannerVersionService $scannerVersionService,
        private readonly FindingDeltaService $findingDeltaService,
    ) {
    }

    public function execute(ScanJob $scanJob): array
    {
        $scanJob = $scanJob->fresh(['scan.requestedBy', 'website', 'scanPlanItem']);

        if (in_array($scanJob->status, [ScanJobStatuses::COMPLETED, ScanJobStatuses::CANCELLED, ScanJobStatuses::SKIPPED], true)) {
            return ['skipped' => true, 'reason' => 'already_terminal'];
        }

        $validation = $this->validate($scanJob);

        if (! $validation['valid']) {
            if (in_array('nuclei_disabled', $validation['errors'], true)) {
                $this->scannerVersionService->record('nuclei', null, null, 'disabled');
                $this->skip($scanJob, 'Nuclei scanner is disabled.', ['errors' => $validation['errors']]);

                return ['skipped' => true, 'errors' => $validation['errors']];
            }

            $this->fail($scanJob, 'Nuclei validation rejected scan job.', ['errors' => $validation['errors']]);

            return ['failed' => true, 'errors' => $validation['errors']];
        }

        if ($this->isCancellationRequested($scanJob)) {
            $this->cancelJob($scanJob, 'Nuclei scan cancelled before execution started.');

            return ['cancelled' => true];
        }

        $worker = $this->workerRegistryService->heartbeat($scanJob);
        $attempt = (int) $scanJob->attempt_count + 1;
        $startedAt = Carbon::now();
        $scanJob = $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::STARTING, 'Nuclei adapter accepted scan job.', [
            'worker_id' => $worker->worker_id,
            'attempt_count' => $attempt,
            'attempts' => $attempt,
            'started_at' => $scanJob->started_at ?? $startedAt,
            'progress' => 5,
            'progress_percent' => 5,
            'last_heartbeat_at' => $startedAt,
        ], [
            'scanner_key' => 'nuclei',
            'scan_module' => $scanJob->scan_module,
            'template_group' => $scanJob->template_group,
        ]);

        $this->markScanStarted($scanJob->scan);

        $sandbox = $this->scannerSandboxService->prepare($scanJob->fresh());
        $outputPath = $sandbox->outputPath('nuclei-output.jsonl');
        $policy = $this->scannerTemplatePolicyService->evaluate('nuclei', $scanJob->template_group);
        $command = $this->buildCommand($scanJob->fresh(['website']), $policy, $outputPath);
        $timeoutSeconds = $this->timeoutSeconds($scanJob);
        $findingCount = 0;
        $metricStatus = 'failed';

        try {
            $scanJob = $this->scanJobLifecycleService->transition($scanJob->fresh(), ScanJobStatuses::RUNNING, 'Nuclei process starting.', [
                'progress' => 10,
                'progress_percent' => 10,
                'last_heartbeat_at' => Carbon::now(),
            ], [
                'command' => $this->sanitizedCommand($command),
                'template_group' => $scanJob->template_group,
                'timeout_seconds' => $timeoutSeconds,
                'max_requests' => $this->maxRequests($scanJob),
            ]);

            $result = $this->scannerProcessRunner->run(
                $command,
                $timeoutSeconds,
                $sandbox->workingDirectory,
                fn (): bool => $this->isCancellationRequested($scanJob->fresh()),
            );

            $rawOutput = File::exists($outputPath) ? File::get($outputPath) : $result->stdout;

            if ($result->cancelled) {
                $metricStatus = 'failed';
                $this->cancelJob($scanJob->fresh(), 'Nuclei scan cancelled during execution.', [
                    'duration_ms' => $result->durationMs,
                ]);

                return ['cancelled' => true];
            }

            if ($result->timedOut) {
                $metricStatus = 'timeout';
                $this->timeoutJob($scanJob->fresh(), 'Nuclei process timed out.', $result->stderr, $result->durationMs);

                return ['timeout' => true];
            }

            if (! $result->successful()) {
                $this->fail($scanJob->fresh(), 'Nuclei process failed.', [
                    'exit_code' => $result->exitCode,
                    'stderr' => mb_substr($result->stderr, 0, 4000),
                    'duration_ms' => $result->durationMs,
                ]);

                return ['failed' => true, 'exit_code' => $result->exitCode];
            }

            $artifact = $this->writeArtifact($scanJob->fresh(), $rawOutput);
            $findings = $this->nucleiFindingNormalizer->persistFindings($scanJob->fresh(['website']), $artifact, $rawOutput);
            $findingCount = count($findings);
            $completedAt = Carbon::now();
            $metricStatus = 'success';
            $resultSummary = [
                'scanner_key' => 'nuclei',
                'template_group' => $scanJob->template_group,
                'findings_count' => $findingCount,
                'raw_artifact_id' => $artifact->id,
                'max_requests' => $this->maxRequests($scanJob),
                'duration_ms' => $result->durationMs,
                'exit_code' => $result->exitCode,
            ];

            $this->scanJobLogService->record($scanJob->fresh(), 'info', 'Nuclei process completed.', [
                'template_group' => $scanJob->template_group,
                'result_count' => $findingCount,
                'raw_artifact_id' => $artifact->id,
            ]);

            $this->scanJobLifecycleService->transition($scanJob->fresh(), ScanJobStatuses::COMPLETED, 'Nuclei adapter completed scan job.', [
                'completed_at' => $completedAt,
                'finished_at' => $completedAt,
                'duration_ms' => $scanJob->started_at ? (int) round($scanJob->started_at->diffInMilliseconds($completedAt)) : $result->durationMs,
                'progress' => 100,
                'progress_percent' => 100,
                'request_count' => min($this->maxRequests($scanJob), max(0, $findingCount)),
                'result_summary' => $resultSummary,
                'error_message' => null,
                'last_heartbeat_at' => $completedAt,
            ]);

            $this->scannerVersionService->record('nuclei', $this->binaryVersion(), $this->templatesVersion(), 'ok', [
                'templates_path' => config('nuclei.templates_path'),
            ]);
            $this->findingDeltaService->recordResolvedForScan($scanJob->scan);
            $this->workerRegistryService->heartbeat($scanJob->fresh());
            $this->scanProgressService->refresh($scanJob->scan);

            return $resultSummary;
        } catch (Throwable $throwable) {
            $this->fail($scanJob->fresh(), 'Nuclei adapter failed scan job.', [
                'exception' => $throwable::class,
                'message' => $throwable->getMessage(),
            ]);

            return ['failed' => true, 'error' => $throwable->getMessage()];
        } finally {
            $durationMs = $scanJob->started_at ? (int) round($scanJob->started_at->diffInMilliseconds(Carbon::now())) : 0;
            $this->scannerRunMetricService->record('nuclei', $metricStatus, $durationMs, $findingCount);
            $this->scannerSandboxService->cleanup($sandbox);
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

        if (! (bool) config('nuclei.enabled', false)) {
            $errors[] = 'nuclei_disabled';
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

        if ($scanJob->website?->host) {
            try {
                $this->targetUrlGuard->assertPublicHost((string) $scanJob->website->host);
            } catch (Throwable) {
                $errors[] = 'target_host_not_public';
            }
        } else {
            $errors[] = 'target_host_missing';
        }

        $policy = $this->scannerTemplatePolicyService->evaluate('nuclei', $scanJob->template_group);

        if (! $policy['allowed']) {
            $errors[] = 'template_policy_blocked';
            $errors[] = (string) ($policy['reason'] ?? 'template_group_not_allowlisted');
        }

        return [
            'valid' => $errors === [],
            'errors' => array_values(array_unique($errors)),
        ];
    }

    public function supports(string $scannerKey, ?string $scanModule = null): bool
    {
        return $scannerKey === 'nuclei';
    }

    /**
     * @param array{allowed: bool, safety_level: string, allowed_tags: list<string>, blocked_tags: list<string>, reason: string|null} $policy
     * @return list<string>
     */
    private function buildCommand(ScanJob $scanJob, array $policy, string $outputPath): array
    {
        $allowedTags = array_values(array_unique(array_filter([
            ...$policy['allowed_tags'],
            ...$this->tagsFromTemplateGroup((string) $scanJob->template_group),
        ])));
        $command = [
            (string) config('nuclei.binary_path', '/usr/local/bin/nuclei'),
            '-u',
            $this->targetUrl($scanJob),
            '-t',
            (string) config('nuclei.templates_path', '/opt/nuclei-templates'),
            '-jsonl',
            '-jle',
            $outputPath,
            '-severity',
            implode(',', (array) config('nuclei.allowed_severities', [])),
            '-exclude-tags',
            implode(',', $policy['blocked_tags']),
            '-rl',
            (string) max(1, (int) config('nuclei.rate_limit_per_second', 2)),
            '-timeout',
            (string) max(1, min(30, $this->timeoutSeconds($scanJob))),
            '-retries',
            '0',
            '-restrict-local-network-access',
            '-no-interactsh',
            '-omit-raw',
            '-omit-template',
            '-silent',
            '-no-color',
            '-rd',
            'authorization,cookie,set-cookie,x-api-key,api-key,token,password,secret',
        ];

        if ($allowedTags !== []) {
            array_splice($command, 12, 0, ['-tags', implode(',', $allowedTags)]);
        }

        return $command;
    }

    /**
     * @return list<string>
     */
    private function tagsFromTemplateGroup(string $templateGroup): array
    {
        $group = trim(str_replace('*', '', $templateGroup), "/ \t\n\r\0\x0B");

        if ($group === '') {
            return [];
        }

        return array_values(array_filter(array_map(
            static fn (string $part): string => trim($part),
            preg_split('#[/_-]+#', $group) ?: [],
        )));
    }

    /**
     * @param list<string> $command
     * @return list<string>
     */
    private function sanitizedCommand(array $command): array
    {
        return array_map(
            static fn (string $part): string => str_contains(strtolower($part), 'token=') ? '[redacted]' : $part,
            $command,
        );
    }

    private function targetUrl(ScanJob $scanJob): string
    {
        $website = $scanJob->website;
        $scheme = $website?->scheme ?: 'https';
        $host = $website?->normalized_host ?: $website?->host;

        return $scheme.'://'.$host;
    }

    private function timeoutSeconds(ScanJob $scanJob): int
    {
        return max(1, min(
            (int) ($scanJob->timeout_seconds ?: config('nuclei.default_timeout_seconds', 300)),
            (int) ($scanJob->max_runtime ?: config('nuclei.default_timeout_seconds', 300)),
            (int) config('nuclei.default_timeout_seconds', 300),
        ));
    }

    private function maxRequests(ScanJob $scanJob): int
    {
        return max(1, min(
            (int) ($scanJob->max_requests ?: config('nuclei.max_requests', 100)),
            (int) config('nuclei.max_requests', 100),
        ));
    }

    private function writeArtifact(ScanJob $scanJob, string $rawOutput): RawArtifact
    {
        $payload = [
            'scanner_key' => 'nuclei',
            'scan_job_id' => $scanJob->id,
            'template_group' => $scanJob->template_group,
            'line_count' => count(array_filter(preg_split('/\r\n|\r|\n/', trim($rawOutput)) ?: [])),
        ];
        $artifact = RawArtifact::query()->create([
            'scan_id' => $scanJob->scan_id,
            'scan_job_id' => $scanJob->id,
            'tool_name' => 'nuclei',
            'scanner_key' => 'nuclei',
            'artifact_type' => 'nuclei_jsonl',
            'json_payload' => $payload,
            'content' => [
                'jsonl' => $rawOutput,
                ...$payload,
            ],
            'sha256' => hash('sha256', $rawOutput),
        ]);

        $this->artifactManifestService->record($artifact, $rawOutput, 'application/jsonl', false, 'scan_raw_default', [
            'scanner_key' => 'nuclei',
            'scan_job_id' => $scanJob->id,
        ]);

        return $artifact;
    }

    private function markScanStarted(?Scan $scan): void
    {
        if (! $scan) {
            return;
        }

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

    /**
     * @param array<string, mixed> $metadata
     */
    private function skip(ScanJob $scanJob, string $reason, array $metadata = []): void
    {
        $now = Carbon::now();
        $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::SKIPPED, $reason, [
            'completed_at' => $now,
            'finished_at' => $now,
            'progress' => 100,
            'progress_percent' => 100,
            'error_message' => null,
        ], $metadata);
        $this->scanProgressService->refresh($scanJob->scan);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function fail(ScanJob $scanJob, string $reason, array $metadata = []): void
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

    private function timeoutJob(ScanJob $scanJob, string $reason, string $stderr, int $durationMs): void
    {
        $now = Carbon::now();
        $this->scanJobLifecycleService->transition($scanJob, ScanJobStatuses::TIMEOUT, $reason, [
            'completed_at' => $now,
            'finished_at' => $now,
            'duration_ms' => $durationMs,
            'progress' => 100,
            'progress_percent' => 100,
            'error_message' => mb_substr($stderr ?: $reason, 0, 4000),
        ], [
            'scanner_key' => 'nuclei',
            'stderr' => mb_substr($stderr, 0, 4000),
        ]);
        $this->scanProgressService->refresh($scanJob->scan);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function cancelJob(ScanJob $scanJob, string $reason, array $metadata = []): void
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

    private function isCancellationRequested(ScanJob $scanJob): bool
    {
        return $scanJob->cancel_requested_at !== null
            || $scanJob->status === ScanJobStatuses::CANCELLED
            || $scanJob->scan?->status === ScanStatuses::CANCELLED;
    }

    private function binaryVersion(): ?string
    {
        $version = config('nuclei.version');

        return is_string($version) && $version !== '' ? $version : null;
    }

    private function templatesVersion(): ?string
    {
        $path = (string) config('nuclei.templates_path', '');

        return $path !== '' ? basename($path) : null;
    }
}
