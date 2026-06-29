<?php

namespace Tests\Feature;

use App\Events\JobQueued;
use App\Events\ScanCompleted;
use App\Events\ScanQueued;
use App\Events\WorkerHeartbeat;
use App\Events\WorkerRegistered;
use App\Models\AuditLog;
use App\Models\RawArtifact;
use App\Models\Scan;
use App\Models\ScanJob;
use App\Models\ScanJobLog;
use App\Models\ScanJobTimeline;
use App\Models\ScanPlan;
use App\Models\ScanPlanItem;
use App\Models\User;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\DnsResolver;
use App\Services\MockExecutorService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

class Phase05ScanOrchestratorTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        for ($id = 1; $id <= 1000; $id++) {
            Cache::lock('scanforge:scan:'.$id, 1)->forceRelease();
        }
    }

    public function test_unverified_website_scan_is_rejected_before_plan_execution(): void
    {
        Bus::fake();
        [$user, $workspace, $website] = $this->workspaceWebsite(verified: false);
        $plan = $this->scanPlan($workspace, $website);
        Sanctum::actingAs($user);

        $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'standard',
            'scan_plan_id' => $plan->id,
            'consent_accepted' => true,
        ])->assertStatus(403)
            ->assertJsonPath('error_code', 'safety_gate_rejected')
            ->assertJsonPath('errors.scan.0', 'domain_not_verified');
    }

    public function test_verified_website_without_scan_plan_returns_409(): void
    {
        [$user, , $website] = $this->workspaceWebsite();
        Sanctum::actingAs($user);

        $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'standard',
            'consent_accepted' => true,
        ])->assertStatus(409)
            ->assertJsonPath('error_code', 'scan_plan_required');
    }

    public function test_verified_ready_scan_plan_creates_scan_and_scan_jobs(): void
    {
        Bus::fake();
        [$user, $workspace, $website] = $this->workspaceWebsite();
        $plan = $this->scanPlan($workspace, $website, items: 2);
        Sanctum::actingAs($user);

        $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'standard',
            'scan_plan_id' => $plan->id,
            'consent_accepted' => true,
        ])->assertAccepted()
            ->assertJsonPath('data.status', 'queued')
            ->assertJsonPath('data.total_jobs', 2)
            ->assertJsonPath('data.jobs.0.queue_name', 'scan-high');

        $this->assertSame(1, Scan::query()->count());
        $this->assertSame(2, ScanJob::query()->count());
        $this->assertDatabaseHas('scan_jobs', [
            'scanner_key' => 'nuclei',
            'status' => 'queued',
            'max_attempts' => 3,
        ]);
        $this->assertSame(2, ScanJobTimeline::query()->where('to_status', 'queued')->count());
        $this->assertDatabaseHas('audit_logs', ['action' => 'scan.queued']);
    }

    public function test_quota_exceeded_returns_429(): void
    {
        [$user, $workspace, $website] = $this->workspaceWebsite();
        $workspace->forceFill(['monthly_scan_limit' => 1, 'scans_used_this_month' => 1])->save();
        $plan = $this->scanPlan($workspace, $website);
        Sanctum::actingAs($user);

        $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'standard',
            'scan_plan_id' => $plan->id,
            'consent_accepted' => true,
        ])->assertStatus(429)
            ->assertJsonPath('error_code', 'quota_exceeded');
    }

    public function test_concurrent_limit_exceeded_returns_429(): void
    {
        [$user, $workspace, $website] = $this->workspaceWebsite();
        $workspace->forceFill(['concurrent_scan_limit' => 1])->save();
        $plan = $this->scanPlan($workspace, $website);
        Scan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_plan_id' => $plan->id,
            'scan_type' => 'standard',
            'status' => 'running',
            'safety_mode' => 'standard',
        ]);
        Sanctum::actingAs($user);

        $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'standard',
            'scan_plan_id' => $plan->id,
            'consent_accepted' => true,
        ])->assertStatus(429)
            ->assertJsonPath('error_code', 'concurrent_scan_limit_exceeded');
    }

    public function test_deep_scan_is_blocked_when_env_flag_is_disabled(): void
    {
        config(['scanforge.scanner.enable_deep_scan' => false]);
        [$user, $workspace, $website] = $this->workspaceWebsite();
        $plan = $this->scanPlan($workspace, $website);
        Sanctum::actingAs($user);

        $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'deep',
            'safety_mode' => 'deep',
            'scan_plan_id' => $plan->id,
            'consent_accepted' => true,
        ])->assertStatus(403)
            ->assertJsonPath('errors.scan.0', 'deep_scan_disabled');
    }

    public function test_authenticated_scan_requires_credential(): void
    {
        [$user, $workspace, $website] = $this->workspaceWebsite();
        $plan = $this->scanPlan($workspace, $website);
        Sanctum::actingAs($user);

        $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'authenticated',
            'safety_mode' => 'authenticated',
            'scan_plan_id' => $plan->id,
            'consent_accepted' => true,
        ])->assertStatus(403)
            ->assertJsonPath('errors.scan.0', 'authenticated_credential_required');
    }

    public function test_cancel_scan_cancels_queued_jobs(): void
    {
        Bus::fake();
        [$user, $workspace, $website] = $this->workspaceWebsite();
        $plan = $this->scanPlan($workspace, $website, items: 2);
        Sanctum::actingAs($user);

        $scanId = $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'standard',
            'scan_plan_id' => $plan->id,
            'consent_accepted' => true,
        ])->assertAccepted()->json('data.id');

        $this->postJson("/api/websites/{$website->id}/scans/{$scanId}/cancel")
            ->assertOk()
            ->assertJsonPath('data.status', 'cancelled');

        $this->assertSame(2, ScanJob::query()->where('status', 'cancelled')->count());
        $this->assertDatabaseHas('audit_logs', ['action' => 'scan.cancel_requested']);
    }

    public function test_retry_failed_requeues_allowed_jobs(): void
    {
        Bus::fake();
        [$user, $workspace, $website] = $this->workspaceWebsite();
        $plan = $this->scanPlan($workspace, $website);
        $scan = Scan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_plan_id' => $plan->id,
            'scan_type' => 'standard',
            'status' => 'failed',
            'safety_mode' => 'standard',
            'total_jobs' => 1,
            'failed_jobs' => 1,
        ]);
        ScanJob::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_id' => $scan->id,
            'scan_plan_item_id' => $plan->items()->firstOrFail()->id,
            'job_type' => 'mock_scan',
            'scanner_key' => 'nuclei',
            'scan_module' => 'framework-cves',
            'template_group' => 'laravel/*',
            'status' => 'failed',
            'priority' => 90,
            'attempt_count' => 1,
            'max_attempts' => 3,
            'progress' => 100,
            'progress_percent' => 100,
            'queue_name' => 'scan-high',
        ]);
        Sanctum::actingAs($user);

        $this->postJson("/api/websites/{$website->id}/scans/{$scan->id}/retry-failed")
            ->assertOk()
            ->assertJsonPath('data.status', 'queued');

        $this->assertDatabaseHas('scan_jobs', [
            'scan_id' => $scan->id,
            'status' => 'queued',
            'attempt_count' => 1,
        ]);
    }

    public function test_mock_executor_completes_job_updates_progress_worker_and_artifacts(): void
    {
        Event::fake([ScanQueued::class, JobQueued::class, ScanCompleted::class, WorkerRegistered::class, WorkerHeartbeat::class]);
        [$user, $workspace, $website] = $this->workspaceWebsite();
        $plan = $this->scanPlan($workspace, $website);
        Sanctum::actingAs($user);

        $scanId = $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'standard',
            'scan_plan_id' => $plan->id,
            'consent_accepted' => true,
        ])->assertAccepted()
            ->assertJsonPath('data.status', 'queued')
            ->json('data.id');

        $scanJob = ScanJob::query()->where('scan_id', $scanId)->firstOrFail();
        app(MockExecutorService::class)->execute($scanJob->id);

        $this->assertDatabaseHas('scan_jobs', [
            'status' => 'completed',
            'progress_percent' => 100,
            'worker_id' => gethostname() ?: 'scanforge-worker',
        ]);
        $this->assertSame(1, RawArtifact::query()->where('artifact_type', 'mock_result')->count());
        $this->assertGreaterThanOrEqual(4, ScanJobLog::query()->count());
        $this->assertDatabaseHas('scan_workers', ['status' => 'online']);
        Event::assertDispatched(ScanCompleted::class);
        Event::assertDispatched(WorkerRegistered::class);
        Event::assertDispatched(WorkerHeartbeat::class);
    }

    public function test_scan_endpoints_are_workspace_scoped(): void
    {
        Bus::fake();
        [$owner, $workspace, $website] = $this->workspaceWebsite(email: 'owner-phase05@example.com');
        $plan = $this->scanPlan($workspace, $website);
        Sanctum::actingAs($owner);
        $scanId = $this->postJson("/api/websites/{$website->id}/scans", [
            'scan_type' => 'standard',
            'scan_plan_id' => $plan->id,
            'consent_accepted' => true,
        ])->assertAccepted()->json('data.id');

        [$other] = $this->workspaceWebsite(email: 'other-phase05@example.com');
        Sanctum::actingAs($other);

        $this->getJson("/api/websites/{$website->id}/scans/{$scanId}")
            ->assertNotFound();
    }

    /**
     * @return array{0: User, 1: Workspace, 2: Website}
     */
    private function workspaceWebsite(bool $verified = true, string $email = 'phase05@example.com'): array
    {
        $this->fakeDns(['example.com' => ['93.184.216.34']]);
        $user = User::query()->create([
            'name' => 'Phase Five',
            'email' => $email,
            'password' => 'password-secure',
        ]);
        $workspace = Workspace::query()->create([
            'name' => 'Phase 05 Workspace',
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

        return [$user, $workspace->fresh(), $website->fresh()];
    }

    private function scanPlan(Workspace $workspace, Website $website, int $items = 1): ScanPlan
    {
        $plan = ScanPlan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'status' => 'ready',
            'coverage_prediction' => 100,
            'estimated_runtime_seconds' => 120 * $items,
            'estimated_requests' => 40 * $items,
            'estimated_cpu' => 0.2,
            'estimated_memory_mb' => 128,
            'safe_mode' => true,
            'analysis_required' => true,
            'generated_from' => 'test',
            'summary' => ['items' => $items],
            'generated_at' => now(),
        ]);

        for ($index = 0; $index < $items; $index++) {
            ScanPlanItem::query()->create([
                'scan_plan_id' => $plan->id,
                'technology_key' => $index === 0 ? 'laravel' : 'nginx',
                'scanner_key' => $index === 0 ? 'nuclei' : 'headers-dns',
                'template_group' => $index === 0 ? 'laravel/*' : 'nginx/*',
                'scan_module' => $index === 0 ? 'framework-cves' : 'server-hardening',
                'priority' => $index === 0 ? 90 : 20,
                'recommendation_score' => 95 - $index,
                'estimated_duration_seconds' => 120,
                'estimated_requests' => 40,
                'estimated_cpu' => 0.2,
                'estimated_memory_mb' => 128,
                'safe_mode' => true,
                'reason' => 'Phase 05 test plan item.',
                'metadata' => ['safe_default' => true],
            ]);
        }

        return $plan->fresh('items');
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
