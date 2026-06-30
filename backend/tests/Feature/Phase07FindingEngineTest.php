<?php

namespace Tests\Feature;

use App\Models\CanonicalFinding;
use App\Models\ConfidenceHistory;
use App\Models\Finding;
use App\Models\FindingEvent;
use App\Models\FindingEvidence;
use App\Models\FindingSource;
use App\Models\RawArtifact;
use App\Models\RiskScoreHistory;
use App\Models\Scan;
use App\Models\ScanJob;
use App\Models\SuppressionRule;
use App\Models\User;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\FindingNormalizationService;
use App\Services\FindingRiskEngine;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

class Phase07FindingEngineTest extends TestCase
{
    use RefreshDatabase;

    public function test_nuclei_jsonl_normalizes_to_canonical_finding_and_engine_records(): void
    {
        [$workspace, $website, , $job, $artifact] = $this->scanFixture();
        Carbon::setTestNow('2026-06-30 10:00:00');

        app(FindingNormalizationService::class)->persistNucleiJsonl($job, $artifact, $this->jsonl(
            templateId: 'cves/2026/CVE-2026-1234',
            cve: 'CVE-2026-1234',
            cwe: 'CWE-89',
            severity: 'high',
            url: 'https://example.com/login?id=1',
        ));

        $finding = Finding::query()->firstOrFail();

        $this->assertSame($workspace->id, $finding->workspace_id);
        $this->assertSame('SQL Injection', $finding->taxonomy?->subcategory);
        $this->assertSame('OWASP A03', $finding->owasp_category);
        $this->assertSame(['CVE-2026-1234'], $finding->cve_json);
        $this->assertSame(['CWE-89'], $finding->cwe_json);
        $this->assertGreaterThan(0, $finding->risk_score);
        $this->assertNotNull($finding->canonical_finding_id);
        $this->assertSame(1, CanonicalFinding::query()->count());
        $this->assertSame(1, FindingSource::query()->count());
        $this->assertSame(1, FindingEvidence::query()->count());
        $this->assertSame(1, RiskScoreHistory::query()->count());
        $this->assertSame(1, ConfidenceHistory::query()->count());
        $this->assertSame(1, FindingEvent::query()->where('new_status', 'new')->count());
    }

    public function test_duplicate_template_and_url_updates_occurrence_without_new_finding(): void
    {
        [, , , $job, $artifact] = $this->scanFixture();
        Carbon::setTestNow('2026-06-30 10:00:00');
        app(FindingNormalizationService::class)->persistNucleiJsonl($job, $artifact, $this->jsonl());
        $firstSeen = Finding::query()->firstOrFail()->first_seen_at;

        Carbon::setTestNow('2026-06-30 10:05:00');
        app(FindingNormalizationService::class)->persistNucleiJsonl($job, $artifact, $this->jsonl());

        $finding = Finding::query()->firstOrFail();

        $this->assertSame(1, Finding::query()->count());
        $this->assertSame(2, $finding->occurrence_count);
        $this->assertTrue($finding->first_seen_at->equalTo($firstSeen));
        $this->assertTrue($finding->last_seen_at->greaterThan($finding->first_seen_at));
        $this->assertSame(2, FindingSource::query()->count());
    }

    public function test_same_cve_on_same_host_correlates_across_templates(): void
    {
        [, , , $job, $artifact] = $this->scanFixture();

        app(FindingNormalizationService::class)->persistNucleiJsonl($job, $artifact, $this->jsonl(
            templateId: 'scanner-a-cve-2026-4444',
            cve: 'CVE-2026-4444',
            url: 'https://example.com/a',
        ));
        app(FindingNormalizationService::class)->persistNucleiJsonl($job, $artifact, $this->jsonl(
            templateId: 'scanner-b-cve-2026-4444',
            cve: 'CVE-2026-4444',
            url: 'https://example.com/b',
        ));

        $finding = Finding::query()->firstOrFail();

        $this->assertSame(1, Finding::query()->count());
        $this->assertSame(2, $finding->occurrence_count);
        $this->assertGreaterThanOrEqual(92, $finding->correlation_score);
        $this->assertSame(2, FindingSource::query()->count());
    }

    public function test_low_confidence_maps_to_high_false_positive_risk(): void
    {
        $this->assertSame('high', app(FindingRiskEngine::class)->falsePositiveRisk(40, 'medium'));
    }

    public function test_finding_api_filters_status_transition_and_workspace_isolation(): void
    {
        [$workspace, $website, $owner, $job, $artifact] = $this->scanFixture();
        app(FindingNormalizationService::class)->persistNucleiJsonl($job, $artifact, $this->jsonl(severity: 'high'));
        $finding = Finding::query()->firstOrFail();

        Sanctum::actingAs($owner);

        $this->getJson("/api/websites/{$website->id}/findings?severity=high")
            ->assertOk()
            ->assertJsonPath('data.0.id', $finding->id)
            ->assertJsonPath('data.0.sources.0.scanner_key', 'nuclei');

        $this->postJson("/api/websites/{$website->id}/findings/{$finding->id}/status", [
            'status' => 'false_positive',
            'reason' => 'Known benign scanner match.',
            'create_rule' => true,
        ])
            ->assertOk()
            ->assertJsonPath('data.status', 'false_positive');

        $this->assertDatabaseHas('finding_events', [
            'finding_id' => $finding->id,
            'old_status' => 'new',
            'new_status' => 'false_positive',
        ]);
        $this->assertSame(1, SuppressionRule::query()->where('action', 'false_positive')->count());

        [$otherWorkspace, , $otherUser] = $this->workspaceWebsite('Other', 'other@example.com');
        $this->assertNotSame($workspace->id, $otherWorkspace->id);
        Sanctum::actingAs($otherUser);

        $this->getJson("/api/websites/{$website->id}/findings")
            ->assertNotFound();
    }

    /**
     * @return array{0: Workspace, 1: Website, 2: User, 3: ScanJob, 4: RawArtifact}
     */
    private function scanFixture(): array
    {
        [$workspace, $website, $user] = $this->workspaceWebsite();
        $scan = Scan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_type' => 'standard',
            'status' => 'running',
            'safe_mode' => true,
            'safety_mode' => 'standard',
            'consent_accepted_at' => now(),
        ]);
        $job = ScanJob::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_id' => $scan->id,
            'job_uuid' => (string) str()->uuid(),
            'job_type' => 'nuclei_scan',
            'scanner_key' => 'nuclei',
            'scan_module' => 'framework-cves',
            'template_group' => 'laravel/*',
            'status' => 'running',
            'priority' => 90,
            'recommendation_score' => 95,
            'safe_default' => true,
            'attempt_count' => 1,
            'max_attempts' => 1,
            'progress' => 50,
            'progress_percent' => 50,
            'queue_name' => 'scan-high',
        ]);
        $artifact = RawArtifact::query()->create([
            'scan_id' => $scan->id,
            'scan_job_id' => $job->id,
            'tool_name' => 'nuclei',
            'scanner_key' => 'nuclei',
            'artifact_type' => 'nuclei_jsonl',
            'json_payload' => [],
            'content' => [],
            'sha256' => hash('sha256', 'test'),
        ]);

        return [$workspace, $website, $user, $job->fresh(), $artifact];
    }

    /**
     * @return array{0: Workspace, 1: Website, 2: User}
     */
    private function workspaceWebsite(string $name = 'Owner', string $email = 'owner@example.com'): array
    {
        $user = User::query()->create([
            'name' => $name,
            'email' => $email,
            'password' => 'password-secure',
        ]);
        $workspace = Workspace::query()->create([
            'name' => $name.' Workspace',
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
            'status' => 'verified',
            'environment' => 'production',
            'importance' => 'critical',
            'verification_status' => 'verified',
            'verified_at' => now(),
            'ownership_verified_at' => now(),
            'metadata' => [],
            'tags' => [],
        ]);

        return [$workspace->fresh(), $website->fresh(), $user->fresh()];
    }

    private function jsonl(
        string $templateId = 'http-missing-csp',
        string $cve = 'CVE-2026-1234',
        string $cwe = 'CWE-693',
        string $severity = 'medium',
        string $url = 'https://example.com/',
    ): string {
        return json_encode([
            'template-id' => $templateId,
            'info' => [
                'name' => 'Missing Content Security Policy',
                'severity' => $severity,
                'description' => 'CSP header was not observed.',
                'remediation' => 'Add a Content-Security-Policy header.',
                'reference' => ['https://developer.mozilla.org/'],
                'classification' => [
                    'cve-id' => [$cve],
                    'cwe-id' => [$cwe],
                    'cvss-score' => 8.8,
                ],
            ],
            'matched-at' => $url,
            'matcher-name' => 'header',
            'timestamp' => '2026-06-30T12:00:00Z',
        ], JSON_THROW_ON_ERROR).PHP_EOL;
    }
}
