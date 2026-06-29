<?php

namespace Tests\Feature;

use App\Models\AssetDiscovery;
use App\Models\CookieObservation;
use App\Models\Finding;
use App\Models\RedirectObservation;
use App\Models\SecurityHeaderObservation;
use App\Models\SslCertificate;
use App\Models\TechnologyFingerprint;
use App\Models\User;
use App\Models\Website;
use App\Models\DomainWhoisSnapshot;
use App\Services\DnsResolver;
use App\Services\SslCertificateService;
use App\Services\WhoisLookupService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

class Phase03AssetDiscoveryTest extends TestCase
{
    use RefreshDatabase;

    public function test_unverified_website_cannot_start_asset_discovery(): void
    {
        $token = $this->registerToken();
        $this->fakeDns(['example.com' => ['93.184.216.34']]);

        $websiteId = $this->withToken($token)->postJson('/api/websites', [
            'url' => 'https://example.com',
        ])->assertCreated()->json('data.website.id');

        $this->withToken($token)
            ->postJson("/api/websites/{$websiteId}/discoveries")
            ->assertStatus(403);
    }

    public function test_verified_website_runs_passive_discovery_and_stores_observations(): void
    {
        [$token, $website] = $this->verifiedWebsite();
        $this->stubPassiveNetwork();

        $this->withToken($token)
            ->postJson("/api/websites/{$website->id}/discoveries")
            ->assertAccepted()
            ->assertJsonPath('data.status', 'completed')
            ->assertJsonPath('data.analysis_required', true);

        $discovery = AssetDiscovery::query()->firstOrFail();

        $this->assertSame('completed', $discovery->status);
        $this->assertNotNull($discovery->dns_completed_at);
        $this->assertNotNull($discovery->http_completed_at);
        $this->assertNotNull($discovery->ssl_completed_at);
        $this->assertNotNull($discovery->whois_completed_at);
        $this->assertGreaterThan(0, $discovery->total_dns_records);
        $this->assertGreaterThan(0, $discovery->total_headers);
        $this->assertSame(2, $discovery->total_cookies);
        $this->assertNotNull($discovery->discovery_score);

        $this->assertDatabaseHas('http_observations', [
            'website_id' => $website->id,
            'body_title' => 'ScanForge Test',
            'html_lang' => 'en',
        ]);
        $this->assertNotNull(Website::query()->findOrFail($website->id)->discovery_completed_at);
        $this->assertSame(9, SecurityHeaderObservation::query()->where('asset_discovery_id', $discovery->id)->count());
        $this->assertSame(2, CookieObservation::query()->where('asset_discovery_id', $discovery->id)->count());
    }

    public function test_private_ip_resolution_blocks_discovery_before_http_probe(): void
    {
        [$token, $website] = $this->verifiedWebsite();
        $this->fakeDns(['example.com' => ['10.0.0.5']]);
        $this->stubSslAndWhois();
        Http::fake(['*' => Http::response('should-not-be-called', 200)]);

        $this->withToken($token)
            ->postJson("/api/websites/{$website->id}/discoveries")
            ->assertAccepted()
            ->assertJsonPath('data.status', 'failed')
            ->assertJsonPath('data.error_message', 'private_or_internal_ip_resolved');

        $this->assertDatabaseHas('findings', [
            'website_id' => $website->id,
            'severity' => 'high',
            'source_tool' => 'scanforge-passive-discovery',
        ]);
        $this->assertDatabaseCount('http_observations', 0);
    }

    public function test_redirect_limit_is_recorded_without_following_foreign_targets(): void
    {
        config(['scanforge.discovery.max_redirects' => 2]);
        [$token, $website] = $this->verifiedWebsite();
        $this->stubSslAndWhois();

        Http::fake(function ($request) {
            $url = (string) $request->url();

            return match ($url) {
                'https://example.com/' => Http::response('', 302, ['Location' => '/one']),
                'https://example.com/one' => Http::response('', 302, ['Location' => '/two']),
                'https://example.com/favicon.ico',
                'https://example.com/robots.txt',
                'https://example.com/sitemap.xml' => Http::response('', 404),
                default => Http::response('', 302, ['Location' => '/three']),
            };
        });

        $this->withToken($token)
            ->postJson("/api/websites/{$website->id}/discoveries")
            ->assertAccepted()
            ->assertJsonPath('data.status', 'completed')
            ->assertJsonPath('data.summary.http.error', 'redirect_limit_exceeded');

        $this->assertSame(2, RedirectObservation::query()->count());
    }

    public function test_missing_security_headers_and_cookie_flags_create_passive_findings(): void
    {
        [$token, $website] = $this->verifiedWebsite();
        $this->stubPassiveNetwork([
            'Server' => 'nginx/1.24.0',
            'Set-Cookie' => 'session=abc; Path=/',
        ], includeDefaultSecurityHeaders: false);

        $this->withToken($token)
            ->postJson("/api/websites/{$website->id}/discoveries")
            ->assertAccepted();

        $titles = Finding::query()
            ->where('website_id', $website->id)
            ->where('source_tool', 'scanforge-passive-discovery')
            ->pluck('title')
            ->all();

        $this->assertContains('Missing HSTS header', $titles);
        $this->assertContains('Missing Content-Security-Policy header', $titles);
        $this->assertContains('Cookie missing Secure flag', $titles);
        $this->assertContains('Cookie missing HttpOnly flag', $titles);
        $this->assertContains('Server header exposes version information', $titles);
    }

    public function test_passive_technology_hints_include_cdn_proxy_framework_and_evidence(): void
    {
        [$token, $website] = $this->verifiedWebsite();
        $this->stubPassiveNetwork();

        $this->withToken($token)
            ->postJson("/api/websites/{$website->id}/discoveries")
            ->assertAccepted();

        $technologyNames = TechnologyFingerprint::query()
            ->where('website_id', $website->id)
            ->pluck('name')
            ->all();

        $this->assertContains('Cloudflare', $technologyNames);
        $this->assertContains('Nginx', $technologyNames);
        $this->assertContains('Laravel', $technologyNames);
        $this->assertContains('React', $technologyNames);
        $this->assertContains('PHP', $technologyNames);

        $laravel = TechnologyFingerprint::query()
            ->where('website_id', $website->id)
            ->where('name', 'Laravel')
            ->firstOrFail();

        $this->assertGreaterThanOrEqual(30, $laravel->confidence_score);
        $this->assertIsArray($laravel->evidence);
    }

    public function test_asset_summary_endpoint_returns_latest_passive_profile(): void
    {
        [$token, $website] = $this->verifiedWebsite();
        $this->stubPassiveNetwork();

        $this->withToken($token)
            ->postJson("/api/websites/{$website->id}/discoveries")
            ->assertAccepted();

        $this->withToken($token)
            ->getJson("/api/websites/{$website->id}/assets/summary")
            ->assertOk()
            ->assertJsonPath('data.host', 'example.com')
            ->assertJsonPath('data.http.status_code', 200)
            ->assertJsonPath('data.security_headers.hsts.present', true)
            ->assertJsonPath('data.cookies.total', 2)
            ->assertJsonStructure(['data' => ['last_discovery', 'ip_addresses', 'technologies', 'passive_findings']]);
    }

    public function test_asset_discovery_endpoints_are_workspace_scoped(): void
    {
        [$ownerToken, $website] = $this->verifiedWebsite('Owner', 'owner@example.com');
        $this->flushHeaders();
        $this->registerToken('Other', 'other@example.com');
        $this->stubPassiveNetwork();
        $owner = User::query()->where('email', 'owner@example.com')->firstOrFail();
        $other = User::query()->where('email', 'other@example.com')->firstOrFail();

        $this->flushHeaders()->withToken($ownerToken)
            ->postJson("/api/websites/{$website->id}/discoveries")
            ->assertAccepted();

        Sanctum::actingAs($other);

        $this->flushHeaders()
            ->getJson("/api/websites/{$website->id}/assets/summary")
            ->assertNotFound();

        $this->flushHeaders()
            ->getJson("/api/websites/{$website->id}/discoveries")
            ->assertNotFound();

        Sanctum::actingAs($owner);

        $this->flushHeaders()
            ->getJson("/api/websites/{$website->id}/assets/summary")
            ->assertOk();
    }

    /**
     * @return array{0: string, 1: Website}
     */
    private function verifiedWebsite(string $name = 'User', string $email = 'user@example.com'): array
    {
        $token = $this->registerToken($name, $email);
        $this->fakeDns(['example.com' => ['93.184.216.34']]);

        $websiteId = $this->withToken($token)->postJson('/api/websites', [
            'url' => 'https://example.com',
        ])->assertCreated()->json('data.website.id');

        Website::query()->whereKey($websiteId)->update([
            'status' => 'verified',
            'verification_status' => 'verified',
            'verified_at' => now(),
            'ownership_verified_at' => now(),
        ]);

        return [$token, Website::query()->findOrFail($websiteId)];
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
     * @param array<string, string|list<string>> $headers
     */
    private function stubPassiveNetwork(array $headers = [], bool $includeDefaultSecurityHeaders = true): void
    {
        $this->fakeDns([
            'example.com' => ['93.184.216.34'],
            'www.example.com' => ['93.184.216.34'],
            '_txt:example.com' => ['v=spf1 include:example.net -all'],
        ]);
        $this->stubSslAndWhois();

        $responseHeaders = [
            'Server' => 'cloudflare, nginx/1.24.0',
            'X-Powered-By' => 'PHP/8.3',
            'CF-Cache-Status' => 'DYNAMIC',
            'Set-Cookie' => [
                'laravel_session=abc; Path=/; Secure; HttpOnly; SameSite=Lax',
                'unsafe_cookie=1; Path=/',
            ],
        ];

        if ($includeDefaultSecurityHeaders) {
            $responseHeaders = array_merge($responseHeaders, [
                'Content-Security-Policy' => "default-src 'self'",
                'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
                'X-Frame-Options' => 'DENY',
                'X-Content-Type-Options' => 'nosniff',
                'Referrer-Policy' => 'strict-origin-when-cross-origin',
            ]);
        }

        $responseHeaders = array_merge($responseHeaders, $headers);

        Http::fake([
            'https://example.com/' => Http::response(
                '<!doctype html><html lang="en"><head><title>ScanForge Test</title><meta name="description" content="Security console"><meta name="generator" content="WordPress 6.5"></head><body><script src="/_next/static/app.js"></script><div id="root" data-reactroot></div></body></html>',
                200,
                $responseHeaders,
            ),
            'https://example.com/favicon.ico' => Http::response('fake-icon', 200, ['Content-Type' => 'image/x-icon']),
            'https://example.com/robots.txt' => Http::response("User-agent: *\nDisallow: /admin\n", 200),
            'https://example.com/sitemap.xml' => Http::response('<urlset></urlset>', 200),
            '*' => Http::response('', 404),
        ]);
    }

    private function stubSslAndWhois(): void
    {
        $this->app->instance(SslCertificateService::class, new class extends SslCertificateService
        {
            public function discover(Website $website, AssetDiscovery $discovery): SslCertificate
            {
                return SslCertificate::query()->create([
                    'workspace_id' => $website->workspace_id,
                    'website_id' => $website->id,
                    'asset_discovery_id' => $discovery->id,
                    'host' => $website->host,
                    'issuer' => 'CN=Test CA',
                    'subject' => 'CN='.$website->host,
                    'valid_from' => now()->subDays(30),
                    'valid_to' => now()->addDays(90),
                    'days_remaining' => 90,
                    'san' => [$website->host, 'www.'.$website->root_domain],
                    'fingerprint_sha256' => hash('sha256', $website->host),
                    'tls_summary' => ['available' => true, 'protocol' => 'TLSv1.3'],
                    'observed_at' => now(),
                ]);
            }
        });

        $this->app->instance(WhoisLookupService::class, new class extends WhoisLookupService
        {
            public function discover(Website $website, AssetDiscovery $discovery): DomainWhoisSnapshot
            {
                return DomainWhoisSnapshot::query()->create([
                    'workspace_id' => $website->workspace_id,
                    'website_id' => $website->id,
                    'asset_discovery_id' => $discovery->id,
                    'registrar' => 'Example Registrar',
                    'created_at_remote' => now()->subYears(5),
                    'expires_at_remote' => now()->addYear(),
                    'age_days' => 1825,
                    'raw_summary' => ['status' => 'available'],
                    'observed_at' => now(),
                ]);
            }
        });
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

            public function records(string $host, array $types): array
            {
                $result = [];

                if (in_array('A', $types, true)) {
                    foreach ($this->records[$host] ?? [] as $ip) {
                        $result[] = [
                            'host' => $host,
                            'type' => 'A',
                            'ip' => $ip,
                            'ttl' => 300,
                        ];
                    }
                }

                if (in_array('TXT', $types, true)) {
                    foreach ($this->records['_txt:'.$host] ?? [] as $txt) {
                        $result[] = [
                            'host' => $host,
                            'type' => 'TXT',
                            'txt' => $txt,
                            'ttl' => 300,
                        ];
                    }
                }

                return $result;
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
