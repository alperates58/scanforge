<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        $now = now();
        $capabilities = [
            [
                'technology_key' => '*',
                'scanner_key' => 'ssl_tls',
                'template_group' => 'ssl',
                'scan_module' => 'ssl',
                'min_confidence' => 0,
                'min_version' => null,
                'max_version' => null,
                'supported_versions' => json_encode(['*']),
                'enabled' => true,
                'safe_default' => true,
                'priority' => 100,
                'estimated_duration_seconds' => 1,
                'estimated_requests' => 0,
                'estimated_cpu' => 0.1,
                'estimated_memory_mb' => 32,
                'safe_mode' => true,
                'description' => 'SSL/TLS Certificate Analysis',
                'created_at' => $now,
                'updated_at' => $now,
            ],
            [
                'technology_key' => '*',
                'scanner_key' => 'dns_security',
                'template_group' => 'dns',
                'scan_module' => 'dns',
                'min_confidence' => 0,
                'min_version' => null,
                'max_version' => null,
                'supported_versions' => json_encode(['*']),
                'enabled' => true,
                'safe_default' => true,
                'priority' => 100,
                'estimated_duration_seconds' => 1,
                'estimated_requests' => 0,
                'estimated_cpu' => 0.1,
                'estimated_memory_mb' => 32,
                'safe_mode' => true,
                'description' => 'DNS Security Records Analysis',
                'created_at' => $now,
                'updated_at' => $now,
            ],
            [
                'technology_key' => '*',
                'scanner_key' => 'http_headers',
                'template_group' => 'headers',
                'scan_module' => 'headers',
                'min_confidence' => 0,
                'min_version' => null,
                'max_version' => null,
                'supported_versions' => json_encode(['*']),
                'enabled' => true,
                'safe_default' => true,
                'priority' => 100,
                'estimated_duration_seconds' => 1,
                'estimated_requests' => 0,
                'estimated_cpu' => 0.1,
                'estimated_memory_mb' => 32,
                'safe_mode' => true,
                'description' => 'HTTP Security Headers Analysis',
                'created_at' => $now,
                'updated_at' => $now,
            ],
            [
                'technology_key' => '*',
                'scanner_key' => 'cookie_security',
                'template_group' => 'cookies',
                'scan_module' => 'cookies',
                'min_confidence' => 0,
                'min_version' => null,
                'max_version' => null,
                'supported_versions' => json_encode(['*']),
                'enabled' => true,
                'safe_default' => true,
                'priority' => 100,
                'estimated_duration_seconds' => 1,
                'estimated_requests' => 0,
                'estimated_cpu' => 0.1,
                'estimated_memory_mb' => 32,
                'safe_mode' => true,
                'description' => 'Cookie Security Attributes Analysis',
                'created_at' => $now,
                'updated_at' => $now,
            ],
        ];

        foreach ($capabilities as $capability) {
            DB::table('scanner_capabilities')->insert($capability);
        }
    }

    public function down(): void
    {
        DB::table('scanner_capabilities')
            ->whereIn('scanner_key', ['ssl_tls', 'dns_security', 'http_headers', 'cookie_security'])
            ->delete();
    }
};
