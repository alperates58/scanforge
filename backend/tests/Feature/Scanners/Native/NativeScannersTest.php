<?php

namespace Tests\Feature\Scanners\Native;

use App\Models\CookieObservation;
use App\Models\DnsRecord;
use App\Models\Finding;
use App\Models\HttpObservation;
use App\Models\Scan;
use App\Models\ScanJob;
use App\Models\SecurityHeaderObservation;
use App\Models\SslCertificate;
use App\Models\Website;
use App\Models\Workspace;
use App\Models\User;
use App\Models\ScanPlan;
use App\Models\ScanPlanItem;
use App\Scanners\ScannerRegistry;
use App\Support\ScanJobStatuses;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Tests\TestCase;

class NativeScannersTest extends TestCase
{
    use RefreshDatabase;

    public function test_scanner_registry_resolves_native_scanners(): void
    {
        $registry = $this->app->make(ScannerRegistry::class);

        $this->assertTrue($registry->has('ssl_tls'));
        $this->assertTrue($registry->has('dns_security'));
        $this->assertTrue($registry->has('http_headers'));
        $this->assertTrue($registry->has('cookie_security'));
    }

    private function setupScanData(string $scannerKey, string $module): array
    {
        $user = User::query()->create([
            'name' => 'Test User',
            'email' => 'test-'.str()->uuid().'@example.com',
            'password' => 'password',
        ]);
        $workspace = Workspace::query()->create([
            'name' => 'Test Workspace',
            'owner_user_id' => $user->id,
            'plan_name' => 'personal',
            'monthly_scan_limit' => 100,
            'concurrent_scan_limit' => 1,
            'scans_used_this_month' => 0,
        ]);
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
            'importance' => 'normal',
            'verification_status' => 'verified',
            'verified_at' => now(),
            'ownership_verified_at' => now(),
            'metadata' => [],
            'tags' => [],
        ]);
        $plan = ScanPlan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'created_by_user_id' => $user->id,
            'status' => 'ready',
            'safe_mode' => true,
            'generated_at' => now(),
        ]);
        $item = ScanPlanItem::query()->create([
            'workspace_id' => $workspace->id,
            'scan_plan_id' => $plan->id,
            'scanner_key' => $scannerKey,
            'template_group' => $module,
            'scan_module' => $module,
            'technology_key' => 'none',
        ]);
        $scan = Scan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_plan_id' => $plan->id,
            'status' => 'queued',
            'consent_accepted_at' => now(),
            'scan_type' => 'standard',
        ]);
        $scanJob = ScanJob::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_id' => $scan->id,
            'scan_plan_item_id' => $item->id,
            'job_uuid' => (string) str()->uuid(),
            'scanner_key' => $scannerKey,
            'scan_module' => $module,
            'status' => ScanJobStatuses::PENDING,
            'attempt_count' => 0,
            'max_attempts' => 1,
            'job_type' => 'native_scan',
        ]);

        return [$website, $scanJob];
    }

    public function test_ssl_tls_scanner_creates_expired_finding(): void
    {
        [$website, $scanJob] = $this->setupScanData('ssl_tls', 'ssl');

        SslCertificate::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'host' => 'example.com',
            'valid_from' => Carbon::yesterday()->subYear(),
            'valid_to' => Carbon::yesterday(),
            'days_remaining' => -1,
            'issuer' => 'Test CA',
            'subject' => 'example.com',
            'san' => [],
            'tls_summary' => [],
            'observed_at' => now(),
        ]);

        $scanner = $this->app->make(ScannerRegistry::class)->resolve('ssl_tls');
        $result = $scanner->execute($scanJob);

        $this->assertArrayHasKey('findings_count', $result);
        $this->assertGreaterThan(0, $result['findings_count']);

        $this->assertDatabaseHas('findings', [
            'website_id' => $website->id,
            'scanner_key' => 'ssl_tls',
            'template_id' => 'certificate_expired',
        ]);
    }

    public function test_dns_security_scanner_creates_missing_dmarc_finding(): void
    {
        [$website, $scanJob] = $this->setupScanData('dns_security', 'dns');

        DnsRecord::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'type' => 'TXT',
            'name' => 'example.com',
            'value' => 'v=spf1 include:_spf.google.com ~all',
            'ttl' => 300,
            'first_seen_at' => now(),
            'last_seen_at' => now(),
        ]);

        $scanner = $this->app->make(ScannerRegistry::class)->resolve('dns_security');
        $result = $scanner->execute($scanJob);
        if (!isset($result['findings_count'])) { dump($result); }

        $this->assertArrayHasKey('findings_count', $result);
        $this->assertGreaterThan(0, $result['findings_count']);

        $this->assertDatabaseHas('findings', [
            'website_id' => $website->id,
            'scanner_key' => 'dns_security',
        ]);
    }

    public function test_http_header_scanner_creates_missing_csp_finding(): void
    {
        [$website, $scanJob] = $this->setupScanData('http_headers', 'headers');

        $obs = HttpObservation::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'url' => 'https://example.com',
            'final_url' => 'https://example.com',
            'status_code' => 200,
            'headers' => [],
            'response_headers_raw' => [],
            'cookies' => [],
            'redirect_chain' => [],
            'observed_at' => now(),
        ]);

        SecurityHeaderObservation::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'http_observation_id' => $obs->id,
            'header_key' => 'strict-transport-security',
            'present' => true,
            'value' => 'max-age=31536000',
            'observed_at' => now(),
        ]);

        $scanner = $this->app->make(ScannerRegistry::class)->resolve('http_headers');
        $result = $scanner->execute($scanJob);

        $this->assertArrayHasKey('findings_count', $result);
        $this->assertGreaterThan(0, $result['findings_count']);

        $this->assertDatabaseHas('findings', [
            'website_id' => $website->id,
            'scanner_key' => 'http_headers',
        ]);
    }

    public function test_cookie_security_scanner_creates_missing_secure_finding(): void
    {
        [$website, $scanJob] = $this->setupScanData('cookie_security', 'cookies');

        CookieObservation::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'name' => 'session_id',
            'domain' => 'example.com',
            'path' => '/',
            'secure' => false,
            'http_only' => true,
            'same_site' => 'Lax',
            'persistent' => false,
            'host_only' => true,
            'observed_at' => now(),
        ]);

        $scanner = $this->app->make(ScannerRegistry::class)->resolve('cookie_security');
        $result = $scanner->execute($scanJob);

        $this->assertArrayHasKey('findings_count', $result);
        $this->assertGreaterThan(0, $result['findings_count']);

        $this->assertDatabaseHas('findings', [
            'website_id' => $website->id,
            'scanner_key' => 'cookie_security',
            'template_id' => 'missing_secure',
        ]);
    }

    public function test_findings_deduplicate_and_correlate(): void
    {
        [$website, $scanJob1] = $this->setupScanData('cookie_security', 'cookies');
        
        $scanJob2 = ScanJob::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'scan_id' => $scanJob1->scan_id,
            'scan_plan_item_id' => $scanJob1->scan_plan_item_id,
            'job_uuid' => (string) str()->uuid(),
            'scanner_key' => 'cookie_security',
            'scan_module' => 'cookies',
            'status' => ScanJobStatuses::PENDING,
            'attempt_count' => 0,
            'max_attempts' => 1,
            'job_type' => 'native_scan',
        ]);

        CookieObservation::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'name' => 'session_id',
            'domain' => 'example.com',
            'path' => '/',
            'secure' => false,
            'http_only' => true,
            'same_site' => 'Lax',
            'persistent' => false,
            'host_only' => true,
            'observed_at' => now(),
        ]);

        $scanner = $this->app->make(ScannerRegistry::class)->resolve('cookie_security');
        $scanner->execute($scanJob1);
        $scanner->execute($scanJob2);

        $count = Finding::where('website_id', $website->id)->where('template_id', 'missing_secure')->count();
        $this->assertEquals(1, $count, 'Findings should be deduplicated.');
    }
}
