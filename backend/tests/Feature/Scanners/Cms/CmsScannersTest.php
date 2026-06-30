<?php

namespace Tests\Feature\Scanners\Cms;

use App\Models\CmsAsset;
use App\Models\HttpObservation;
use App\Models\Scan;
use App\Models\ScanJob;
use App\Models\User;
use App\Models\Website;
use App\Models\Workspace;
use App\Scanners\Native\CmsScannerAdapter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class CmsScannersTest extends TestCase
{
    use RefreshDatabase;

    private function createDependencies(string $module): array
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
            'environment' => 'production',
            'importance' => 'normal',
            'status' => 'verified',
            'verification_status' => 'verified',
            'verified_at' => now(),
            'ownership_verified_at' => now(),
        ]);
        $plan = \App\Models\ScanPlan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'created_by_user_id' => $user->id,
            'status' => 'ready',
            'safe_mode' => true,
            'generated_at' => now(),
        ]);
        $item = \App\Models\ScanPlanItem::query()->create([
            'workspace_id' => $workspace->id,
            'scan_plan_id' => $plan->id,
            'scanner_key' => 'cms_scanner',
            'template_group' => $module,
            'scan_module' => $module,
            'technology_key' => 'none',
        ]);
        $scan = Scan::query()->create([
            'workspace_id' => $workspace->id,
            'website_id' => $website->id,
            'scan_plan_id' => $plan->id,
            'status' => 'running',
            'scan_type' => 'standard',
            'requested_by_user_id' => $user->id,
            'consent_accepted_at' => now(),
        ]);

        return [$workspace, $website, $scan, $item];
    }

    public function test_wordpress_plugin_extracts_cms_assets_from_html(): void
    {
        [$workspace, $website, $scan, $item] = $this->createDependencies('wordpress_cms');

        HttpObservation::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'url' => 'https://example.com/',
            'method' => 'GET',
            'path' => '/',
            'response_status' => 200,
            'response_body' => '<html><head><meta name="generator" content="WordPress 6.2" /></head><body><script src="/wp-content/plugins/contact-form-7/js/index.js"></script><link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css" /></body></html>',
            'generator_meta' => 'WordPress 6.2',
            'observed_at' => Carbon::now(),
        ]);

        $scanJob = ScanJob::query()->create([
            'workspace_id' => $website->workspace_id,
            'scan_id' => $scan->id,
            'website_id' => $website->id,
            'scan_plan_item_id' => $item->id,
            'scanner_key' => 'cms_scanner',
            'scan_module' => 'wordpress_cms',
            'status' => 'pending',
            'job_type' => 'native',
        ]);

        Http::fake([
            'https://example.com' => Http::response('<html><head><meta name="generator" content="WordPress 6.2" /></head><body><script src="/wp-content/plugins/contact-form-7/js/index.js"></script><link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css" /></body></html>', 200),
            'https://example.com/' => Http::response('<html><head><meta name="generator" content="WordPress 6.2" /></head><body><script src="/wp-content/plugins/contact-form-7/js/index.js"></script><link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css" /></body></html>', 200),
            '*/xmlrpc.php' => Http::response('', 405),
            '*/wp-json/' => Http::response('{"routes":{}}', 200),
        ]);

        $adapter = app(CmsScannerAdapter::class);
        $adapter->execute($scanJob);

        $this->assertDatabaseHas('cms_assets', [
            'website_id' => $website->id,
            'cms_name' => 'WordPress',
            'asset_type' => 'plugin',
            'asset_name' => 'contact-form-7',
        ]);

        $this->assertDatabaseHas('cms_assets', [
            'website_id' => $website->id,
            'cms_name' => 'WordPress',
            'asset_type' => 'theme',
            'asset_name' => 'twentytwentythree',
        ]);

        $this->assertDatabaseHas('findings', [
            'website_id' => $website->id,
            'scanner_key' => 'cms_scanner',
        ]);
        
        app(\App\Services\WebsiteRiskRollupService::class)->refresh($website);

        $this->assertDatabaseHas('websites', [
            'id' => $website->id,
            'cms_detected' => true,
        ]);
    }

    public function test_generic_cms_plugin_identifies_generator(): void
    {
        [$workspace, $website, $scan, $item] = $this->createDependencies('generic_cms');

        HttpObservation::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'url' => 'https://example.com/',
            'method' => 'GET',
            'path' => '/',
            'response_status' => 200,
            'response_body' => '<html><head><meta name="generator" content="Joomla! - Open Source Content Management" /></head><body></body></html>',
            'generator_meta' => 'Joomla! - Open Source Content Management',
            'observed_at' => Carbon::now(),
        ]);

        $scanJob = ScanJob::query()->create([
            'workspace_id' => $website->workspace_id,
            'scan_id' => $scan->id,
            'website_id' => $website->id,
            'scan_plan_item_id' => $item->id,
            'scanner_key' => 'cms_scanner',
            'scan_module' => 'generic_cms',
            'status' => 'pending',
            'job_type' => 'native',
        ]);

        $adapter = app(CmsScannerAdapter::class);
        $adapter->execute($scanJob);

        $this->assertDatabaseHas('findings', [
            'website_id' => $website->id,
            'scanner_key' => 'cms_scanner',
        ]);
    }
}
