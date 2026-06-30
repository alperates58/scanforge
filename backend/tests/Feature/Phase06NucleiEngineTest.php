<?php

namespace Tests\Feature;

use App\Models\ArtifactManifest;
use App\Models\Finding;
use App\Models\RawArtifact;
use App\Models\Scan;
use App\Models\ScannerMetric;
use App\Models\ScannerVersion;
use App\Models\ScanJob;
use App\Models\ScanPlan;
use App\Models\ScanPlanItem;
use App\Models\User;
use App\Models\Website;
use App\Models\Workspace;
use App\Scanners\Contracts\ScannerProcessRunnerInterface;
use App\Scanners\Support\ScannerProcessResult;
use App\Services\DnsResolver;
use App\Services\ScannerExecutorService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

class Phase06NucleiEngineTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        config([
            'nuclei.enabled' => true,
            'nuclei.default_timeout_seconds' => 30,
            'nuclei.max_requests' => 20,
            'nuclei.rate_limit_per_second' => 2,
            'scanners.fallback_to_mock' => false,
        ]);
        $this->fakeDns(['example.com' => ['93.184.216.34']]);
    }

    public function test_disabled_nuclei_job_is_skipped_safely(): void
    {
        config(['nuclei.enabled' => false]);
        $runner = new FakeNucleiProcessRunner('');
        $this->app->instance(ScannerProcessRunnerInterface::class, $runner);
        [, , , $job] = $this->scanJob();

        app(ScannerExecutorService::class)->execute($job->id);

        $this->assertSame('skipped', $job->fresh()->status);
        $this->assertSame([], $runner->commands);
        $this->assertDatabaseHas('scanner_versions', [
            'scanner_key' => 'nuclei',
            'status' => 'disabled',
        ]);
    }

    public function test_unverified_website_nuclei_execution_is_rejected(): void
    {
        $runner = new FakeNucleiProcessRunner('');
        $this->app->instance(ScannerProcessRunnerInterface::class, $runner);
        [, , , $job] = $this->scanJob(verified: false);

        app(ScannerExecutorService::class)->execute($job->id);

        $this->assertSame('failed', $job->fresh()->status);
        $this->assertStringContainsString('Nuclei validation rejected', (string) $job->fresh()->error_message);
        $this->assertSame([], $runner->commands);
    }

    public function test_template_policy_blocks_intrusive_group(): void
    {
        $runner = new FakeNucleiProcessRunner('');
        $this->app->instance(ScannerProcessRunnerInterface::class, $runner);
        [, , , $job] = $this->scanJob(templateGroup: 'intrusive');

        app(ScannerExecutorService::class)->execute($job->id);

        $this->assertSame('failed', $job->fresh()->status);
        $this->assertSame([], $runner->commands);
    }

    public function test_fake_nuclei_jsonl_creates_artifact_manifest_finding_and_deduplicates(): void
    {
        $jsonl = json_encode([
            'template-id' => 'http-missing-csp',
            'info' => [
                'name' => 'Missing Content Security Policy',
                'severity' => 'medium',
                'description' => 'CSP header was not observed.',
                'remediation' => 'Add a Content-Security-Policy header.',
                'reference' => ['https://developer.mozilla.org/'],
                'classification' => ['cwe-id' => ['CWE-693']],
            ],
            'matched-at' => 'https://example.com/',
            'matcher-name' => 'header',
            'timestamp' => '2026-06-30T12:00:00Z',
        ], JSON_THROW_ON_ERROR).PHP_EOL;
        $runner = new FakeNucleiProcessRunner($jsonl);
        $this->app->instance(ScannerProcessRunnerInterface::class, $runner);
        [$workspace, $website] = $this->workspaceWebsite();
        $firstJob = $this->scanJobFor($workspace, $website)[3];
        $secondJob = $this->scanJobFor($workspace, $website)[3];

        app(ScannerExecutorService::class)->execute($firstJob->id);
        app(ScannerExecutorService::class)->execute($secondJob->id);

        $this->assertSame('completed', $firstJob->fresh()->status);
        $this->assertSame('completed', $secondJob->fresh()->status);
        $this->assertSame(2, RawArtifact::query()->where('artifact_type', 'nuclei_jsonl')->count());
        $this->assertSame(2, ArtifactManifest::query()->count());
        $this->assertSame(1, Finding::query()->where('scanner_key', 'nuclei')->count());
        $finding = Finding::query()->where('scanner_key', 'nuclei')->firstOrFail();
        $this->assertSame('http-missing-csp', $finding->template_id);
        $this->assertSame(2, $finding->occurrence_count);
        $this->assertSame('new', $finding->status);
        $this->assertDatabaseHas('scanner_metrics', [
            'scanner_key' => 'nuclei',
            'runs' => 2,
            'success' => 2,
        ]);
        $this->assertNotEmpty($runner->commands);
        $this->assertContains('-u', $runner->commands[0]);
        $this->assertContains('-restrict-local-network-access', $runner->commands[0]);
    }

    public function test_timeout_marks_job_timeout(): void
    {
        $runner = new FakeNucleiProcessRunner('', timedOut: true, exitCode: 1, stderr: 'timeout');
        $this->app->instance(ScannerProcessRunnerInterface::class, $runner);
        [, , , $job] = $this->scanJob();

        app(ScannerExecutorService::class)->execute($job->id);

        $this->assertSame('timeout', $job->fresh()->status);
        $this->assertDatabaseHas('scanner_metrics', [
            'scanner_key' => 'nuclei',
            'timeout' => 1,
        ]);
    }

    public function test_cancellation_before_process_is_respected(): void
    {
        $runner = new FakeNucleiProcessRunner('');
        $this->app->instance(ScannerProcessRunnerInterface::class, $runner);
        [, , , $job] = $this->scanJob();
        $job->forceFill(['cancel_requested_at' => now()])->save();

        app(ScannerExecutorService::class)->execute($job->id);

        $this->assertSame('cancelled', $job->fresh()->status);
        $this->assertSame([], $runner->commands);
    }

    /**
     * @return array{0: Workspace, 1: Website, 2: Scan, 3: ScanJob}
     */
    private function scanJob(bool $verified = true, string $templateGroup = 'laravel/*'): array
    {
        [$workspace, $website] = $this->workspaceWebsite($verified);

        return $this->scanJobFor($workspace, $website, $templateGroup);
    }

    /**
     * @return array{0: Workspace, 1: Website, 2: Scan, 3: ScanJob}
     */
    private function scanJobFor(Workspace $workspace, Website $website, string $templateGroup = 'laravel/*'): array
    {
        $plan = ScanPlan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'status' => 'ready',
            'coverage_prediction' => 100,
            'estimated_runtime_seconds' => 60,
            'estimated_requests' => 10,
            'estimated_cpu' => 0.1,
            'estimated_memory_mb' => 128,
            'safe_mode' => true,
            'analysis_required' => true,
            'generated_from' => 'test',
            'generated_at' => now(),
        ]);
        $item = ScanPlanItem::query()->create([
            'scan_plan_id' => $plan->id,
            'technology_key' => 'laravel',
            'scanner_key' => 'nuclei',
            'template_group' => $templateGroup,
            'scan_module' => 'framework-cves',
            'priority' => 90,
            'recommendation_score' => 95,
            'estimated_duration_seconds' => 60,
            'estimated_requests' => 10,
            'estimated_cpu' => 0.1,
            'estimated_memory_mb' => 128,
            'safe_mode' => true,
            'reason' => 'Phase 06 test item.',
            'metadata' => ['safe_default' => true],
        ]);
        $scan = Scan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_plan_id' => $plan->id,
            'scan_type' => 'standard',
            'status' => 'queued',
            'safe_mode' => true,
            'safety_mode' => 'standard',
            'consent_accepted_at' => now(),
            'request_budget' => 10,
            'timeout_seconds' => 60,
            'total_jobs' => 1,
        ]);
        $job = ScanJob::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_id' => $scan->id,
            'scan_plan_item_id' => $item->id,
            'job_uuid' => (string) str()->uuid(),
            'job_type' => 'nuclei_scan',
            'scanner_key' => 'nuclei',
            'scan_module' => 'framework-cves',
            'template_group' => $templateGroup,
            'status' => 'queued',
            'priority' => 90,
            'recommendation_score' => 95,
            'safe_default' => true,
            'attempt_count' => 0,
            'max_attempts' => 1,
            'timeout_seconds' => 60,
            'progress' => 0,
            'progress_percent' => 0,
            'queue_name' => 'scan-high',
            'max_requests' => 10,
            'max_runtime' => 60,
            'max_memory' => 128,
            'cancellation_token' => (string) str()->uuid(),
        ]);

        return [$workspace, $website, $scan, $job];
    }

    /**
     * @return array{0: Workspace, 1: Website}
     */
    private function workspaceWebsite(bool $verified = true): array
    {
        $user = User::query()->create([
            'name' => 'Phase Six',
            'email' => 'phase06-'.str()->uuid().'@example.com',
            'password' => 'password-secure',
        ]);
        $workspace = Workspace::query()->create([
            'name' => 'Phase 06 Workspace',
            'owner_user_id' => $user->id,
            'plan_name' => 'personal',
            'monthly_scan_limit' => 100,
            'concurrent_scan_limit' => 1,
            'scans_used_this_month' => 0,
        ]);
        $workspace->members()->attach($user->id, ['role' => 'owner']);
        $website = Website::query()->create([
            'workspace_id' => $workspace->id,
            'created_by_user_id' => $user->id,
            'url' => 'https://example.com',
            'scheme' => 'https',
            'host' => 'example.com',
            'root_domain' => 'example.com',
            'normalized_host' => 'example.com',
            'status' => $verified ? 'verified' : 'pending_verification',
            'environment' => 'production',
            'importance' => 'normal',
            'verification_status' => $verified ? 'verified' : 'pending',
            'verified_at' => $verified ? now() : null,
            'ownership_verified_at' => $verified ? now() : null,
            'metadata' => [],
            'tags' => [],
        ]);

        return [$workspace->fresh(), $website->fresh()];
    }

    /**
     * @param array<string, list<string>> $records
     */
    private function fakeDns(array $records): void
    {
        $this->app->instance(DnsResolver::class, new class($records) extends DnsResolver
        {
            /**
             * @param array<string, list<string>> $records
             */
            public function __construct(private readonly array $records)
            {
            }

            public function resolveIps(string $host): array
            {
                return $this->records[$host] ?? [];
            }
        });
    }
}

class FakeNucleiProcessRunner implements ScannerProcessRunnerInterface
{
    /** @var list<list<string>> */
    public array $commands = [];

    public function __construct(
        private readonly string $stdout,
        private readonly bool $timedOut = false,
        private readonly int $exitCode = 0,
        private readonly string $stderr = '',
    ) {
    }

    public function run(array $command, int $timeoutSeconds, string $workingDirectory, ?callable $shouldCancel = null): ScannerProcessResult
    {
        $this->commands[] = $command;

        return new ScannerProcessResult(
            exitCode: $this->exitCode,
            stdout: $this->stdout,
            stderr: $this->stderr,
            timedOut: $this->timedOut,
            cancelled: $shouldCancel ? $shouldCancel() : false,
            durationMs: 123,
        );
    }
}
