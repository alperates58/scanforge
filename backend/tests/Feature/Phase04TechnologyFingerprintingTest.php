<?php

namespace Tests\Feature;

use App\Models\AssetDiscovery;
use App\Models\CookieObservation;
use App\Models\HttpObservation;
use App\Models\TechnologyEvidence;
use App\Models\TechnologyFingerprint;
use App\Models\TechnologyRelationship;
use App\Models\Website;
use Illuminate\Foundation\Testing\RefreshDatabase;
use RuntimeException;
use Tests\TestCase;

class Phase04TechnologyFingerprintingTest extends TestCase
{
    use RefreshDatabase;

    public function test_verified_website_generates_rule_based_fingerprints_evidence_and_relationships(): void
    {
        [$token, $website] = $this->verifiedWebsiteWithPassiveObservations();

        $this->withToken($token)
            ->postJson("/api/websites/{$website->id}/fingerprint")
            ->assertAccepted()
            ->assertJsonPath('data.coverage.items.server.present', true)
            ->assertJsonPath('data.coverage.items.cms.present', true);

        $this->assertDatabaseHas('technology_fingerprints', [
            'website_id' => $website->id,
            'technology_key' => 'wordpress',
            'analysis_required' => true,
        ]);
        $this->assertDatabaseHas('technology_fingerprints', [
            'website_id' => $website->id,
            'technology_key' => 'laravel',
            'analysis_required' => true,
        ]);

        $this->assertGreaterThan(0, TechnologyEvidence::query()->where('website_id', $website->id)->count());
        $this->assertGreaterThan(0, TechnologyRelationship::query()->where('website_id', $website->id)->count());

        $wordpress = TechnologyFingerprint::query()->where('technology_key', 'wordpress')->firstOrFail();
        $this->assertSame('6.5', $wordpress->version);
        $this->assertGreaterThanOrEqual(80, $wordpress->confidence_score);
        $this->assertGreaterThanOrEqual(50, $wordpress->quality_score);
        $this->assertIsArray($wordpress->cpe_candidates);
    }

    public function test_scan_plan_uses_capability_resolver_with_recommendation_scores_and_cost_estimates(): void
    {
        [$token, $website] = $this->verifiedWebsiteWithPassiveObservations();

        $this->withToken($token)->postJson("/api/websites/{$website->id}/fingerprint")->assertAccepted();

        $this->withToken($token)
            ->postJson("/api/websites/{$website->id}/scan-plans")
            ->assertCreated()
            ->assertJsonPath('data.safe_mode', true)
            ->assertJsonPath('data.items.0.safe_mode', true)
            ->assertJsonStructure([
                'data' => [
                    'coverage_prediction',
                    'estimated_runtime_seconds',
                    'estimated_requests',
                    'estimated_cpu',
                    'estimated_memory_mb',
                    'items' => [
                        ['technology_key', 'scanner_key', 'template_group', 'recommendation_score'],
                    ],
                ],
            ]);

        $this->assertDatabaseHas('scan_plan_items', [
            'scanner_key' => 'wpscan',
            'template_group' => 'core/plugins/themes',
        ]);
    }

    public function test_technology_graph_export_is_ai_ready_json(): void
    {
        [$token, $website] = $this->verifiedWebsiteWithPassiveObservations();

        $this->withToken($token)->postJson("/api/websites/{$website->id}/fingerprint")->assertAccepted();
        $this->withToken($token)->postJson("/api/websites/{$website->id}/scan-plans")->assertCreated();

        $this->withToken($token)
            ->getJson("/api/websites/{$website->id}/technology-graph")
            ->assertOk()
            ->assertJsonPath('data.website.host', 'example.com')
            ->assertJsonStructure([
                'data' => [
                    'website',
                    'asset_graph' => ['host', 'ssl', 'headers', 'cookies'],
                    'technologies',
                    'relationships',
                    'latest_scan_plan',
                ],
            ]);
    }

    public function test_technology_evidence_is_immutable_after_creation(): void
    {
        [$token, $website] = $this->verifiedWebsiteWithPassiveObservations();
        $this->withToken($token)->postJson("/api/websites/{$website->id}/fingerprint")->assertAccepted();

        $evidence = TechnologyEvidence::query()->firstOrFail();
        $evidence->source_value = 'mutated';

        $this->expectException(RuntimeException::class);
        $evidence->save();
    }

    /**
     * @return array{0: string, 1: Website}
     */
    private function verifiedWebsiteWithPassiveObservations(): array
    {
        $token = (string) $this->postJson('/api/auth/register', [
            'name' => 'Phase Four',
            'email' => 'phase04@example.com',
            'password' => 'password-secure',
        ])->assertCreated()->json('data.token');

        $websiteId = $this->withToken($token)->postJson('/api/websites', [
            'url' => 'https://example.com',
        ])->assertCreated()->json('data.website.id');

        $website = Website::query()->findOrFail($websiteId);
        $website->forceFill([
            'status' => 'verified',
            'verification_status' => 'verified',
            'verified_at' => now(),
            'ownership_verified_at' => now(),
        ])->save();

        $discovery = AssetDiscovery::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'status' => 'completed',
            'started_at' => now()->subSeconds(5),
            'dns_completed_at' => now()->subSeconds(4),
            'http_completed_at' => now()->subSeconds(3),
            'ssl_completed_at' => now()->subSeconds(2),
            'whois_completed_at' => now()->subSecond(),
            'completed_at' => now(),
            'analysis_required' => true,
            'discovery_score' => 84,
        ]);

        $httpObservation = HttpObservation::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'asset_discovery_id' => $discovery->id,
            'url' => 'https://example.com/',
            'final_url' => 'https://example.com/',
            'status_code' => 200,
            'server_header' => 'cloudflare, nginx/1.24.0',
            'powered_by_header' => 'PHP/8.3',
            'headers' => [
                'Server' => 'cloudflare, nginx/1.24.0',
                'X-Powered-By' => 'PHP/8.3',
                'CF-Cache-Status' => 'DYNAMIC',
            ],
            'body_hash_sha256' => hash('sha256', 'phase04'),
            'body_title' => 'Phase 04 Test',
            'body_description' => 'WordPress and Laravel test fixture',
            'generator_meta' => 'WordPress 6.5',
            'observed_at' => now(),
        ]);

        foreach (['laravel_session', '__cf_bm', 'PHPSESSID'] as $cookieName) {
            CookieObservation::query()->create([
                'workspace_id' => $website->workspace_id,
                'website_id' => $website->id,
                'asset_discovery_id' => $discovery->id,
                'http_observation_id' => $httpObservation->id,
                'name' => $cookieName,
                'path' => '/',
                'secure' => true,
                'http_only' => true,
                'same_site' => 'Lax',
                'persistent' => false,
                'host_only' => true,
                'observed_at' => now(),
            ]);
        }

        return [$token, $website->fresh()];
    }
}
