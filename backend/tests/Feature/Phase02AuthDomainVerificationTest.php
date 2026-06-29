<?php

namespace Tests\Feature;

use App\Models\DomainVerification;
use App\Models\Scan;
use App\Models\ScanJob;
use App\Models\User;
use App\Models\Website;
use App\Services\DnsResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

class Phase02AuthDomainVerificationTest extends TestCase
{
    use RefreshDatabase;

    public function test_register_login_and_me_create_default_workspace(): void
    {
        $register = $this->postJson('/api/auth/register', [
            'name' => 'Grace Hopper',
            'email' => 'grace@example.com',
            'password' => 'password-secure',
        ]);

        $register->assertCreated()
            ->assertJsonPath('data.user.email', 'grace@example.com')
            ->assertJsonPath('data.workspace.plan_name', 'personal')
            ->assertJsonPath('data.workspace.monthly_scan_limit', 100)
            ->assertJsonPath('data.workspace.concurrent_scan_limit', 1);

        $login = $this->postJson('/api/auth/login', [
            'email' => 'grace@example.com',
            'password' => 'password-secure',
        ]);

        $login->assertOk()->assertJsonStructure(['data' => ['token']]);

        $this->withToken($login->json('data.token'))
            ->getJson('/api/me')
            ->assertOk()
            ->assertJsonPath('data.workspaces.0.plan_name', 'personal');
    }

    public function test_website_create_normalizes_url_and_hashes_verification_token(): void
    {
        $token = $this->registerToken();
        $this->fakeDns(['example.com' => ['93.184.216.34']]);

        $response = $this->withToken($token)->postJson('/api/websites', [
            'url' => 'https://Example.COM:443/admin',
            'environment' => 'production',
            'importance' => 'critical',
            'tags' => ['production', 'customer'],
        ]);

        $response->assertCreated()
            ->assertJsonPath('data.website.url', 'https://example.com')
            ->assertJsonPath('data.website.host', 'example.com')
            ->assertJsonPath('data.website.root_domain', 'example.com')
            ->assertJsonPath('data.website.importance', 'critical')
            ->assertJsonPath('data.website.tags.0', 'production')
            ->assertJsonStructure(['data' => ['verification' => ['token', 'methods']]]);

        $website = Website::query()->firstOrFail();

        $this->assertNotNull($website->verification_token_hash);
        $this->assertFalse(Schema::hasColumn('websites', 'verification_token'));
        $this->assertFalse(Schema::hasColumn('domain_verifications', 'token'));
        $this->assertSame(3, DomainVerification::query()->where('website_id', $website->id)->count());
    }

    public function test_private_ip_and_localhost_targets_are_rejected(): void
    {
        $token = $this->registerToken();

        $this->withToken($token)
            ->postJson('/api/websites', ['url' => 'http://127.0.0.1'])
            ->assertStatus(422);

        $this->withToken($token)
            ->postJson('/api/websites', ['url' => 'http://localhost'])
            ->assertStatus(422);
    }

    public function test_unverified_scan_is_rejected_and_verified_scan_now_requires_scan_plan(): void
    {
        $token = $this->registerToken();
        $this->fakeDns(['example.com' => ['93.184.216.34']]);

        $created = $this->withToken($token)->postJson('/api/websites', [
            'url' => 'https://example.com',
        ])->assertCreated();

        $websiteId = $created->json('data.website.id');

        $this->withToken($token)->postJson("/api/websites/{$websiteId}/scans", [
            'scan_type' => 'passive',
            'consent_accepted' => true,
        ])->assertStatus(403)
            ->assertJsonPath('errors.scan.0', 'domain_not_verified');

        Website::query()->whereKey($websiteId)->update([
            'status' => 'verified',
            'verification_status' => 'verified',
            'verified_at' => now(),
            'ownership_verified_at' => now(),
        ]);

        $this->withToken($token)->postJson("/api/websites/{$websiteId}/scans", [
            'scan_type' => 'passive',
            'consent_accepted' => true,
        ])->assertStatus(409)
            ->assertJsonPath('error_code', 'scan_plan_required');

        $this->assertSame(0, Scan::query()->count());
        $this->assertSame(0, ScanJob::query()->count());
    }

    public function test_verification_check_can_verify_with_dns_txt_without_logging_plain_token(): void
    {
        $token = $this->registerToken();
        $this->fakeDns(['example.com' => ['93.184.216.34']]);

        $created = $this->withToken($token)->postJson('/api/websites', [
            'url' => 'https://example.com',
        ])->assertCreated();

        $websiteId = $created->json('data.website.id');
        $verificationToken = $created->json('data.verification.token');

        $this->fakeDns([
            'example.com' => ['93.184.216.34'],
            '_txt:example.com' => ['scanforge-verify='.$verificationToken],
        ]);

        Http::fake(['*' => Http::response('', 404)]);

        $this->withToken($token)
            ->postJson("/api/websites/{$websiteId}/verification/check")
            ->assertOk()
            ->assertJsonPath('data.verified', true)
            ->assertJsonPath('data.verified_method', 'dns_txt');

        $website = Website::query()->findOrFail($websiteId);

        $this->assertTrue($website->isVerified());
        $auditMetadata = json_encode(\App\Models\AuditLog::query()->pluck('metadata')->all());

        $this->assertIsString($auditMetadata);
        $this->assertStringNotContainsString($verificationToken, $auditMetadata);
    }

    public function test_workspace_isolation_blocks_other_users_websites(): void
    {
        $this->registerToken('Owner', 'owner@example.com');
        $this->registerToken('Other', 'other@example.com');
        $owner = User::query()->where('email', 'owner@example.com')->firstOrFail();
        $other = User::query()->where('email', 'other@example.com')->firstOrFail();
        $this->fakeDns(['example.com' => ['93.184.216.34']]);

        Sanctum::actingAs($owner);

        $created = $this->flushHeaders()->postJson('/api/websites', [
            'url' => 'https://example.com',
        ])->assertCreated();

        Sanctum::actingAs($other);

        $this->flushHeaders()
            ->getJson('/api/websites/'.$created->json('data.website.id'))
            ->assertNotFound();
    }

    private function registerToken(string $name = 'User', string $email = 'user@example.com'): string
    {
        return (string) $this->postJson('/api/auth/register', [
            'name' => $name,
            'email' => $email,
            'password' => 'password-secure',
        ])->assertCreated()->json('data.token');
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

            public function txtRecords(string $host): array
            {
                return $this->records['_txt:'.$host] ?? [];
            }
        });
    }
}
