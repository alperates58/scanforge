<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ExampleTest extends TestCase
{
    use RefreshDatabase;

    public function test_health_endpoint_reports_dependencies(): void
    {
        $response = $this->getJson('/api/health');

        $response->assertStatus(200);
        $response->assertJsonPath('status', 'ok');
        $response->assertJsonPath('dependencies.database.ok', true);
        $response->assertJsonPath('dependencies.redis.ok', true);
    }

    public function test_dashboard_summary_uses_safe_zero_defaults(): void
    {
        $register = $this->postJson('/api/auth/register', [
            'name' => 'Ada Lovelace',
            'email' => 'ada@example.com',
            'password' => 'password-secure',
        ]);

        $response = $this
            ->withToken($register->json('data.token'))
            ->getJson('/api/dashboard/summary');

        $response->assertStatus(200);
        $response->assertJsonPath('schema_ready', true);
        $response->assertJsonPath('totals.websites', 0);
        $response->assertJsonPath('safety.unverified_domain_scans_allowed', false);
    }
}
