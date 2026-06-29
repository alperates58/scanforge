<?php

namespace Database\Seeders;

use App\Models\ScannerCapability;
use Illuminate\Database\Seeder;

class ScannerCapabilitySeeder extends Seeder
{
    public function run(): void
    {
        foreach (config('scanner_capabilities', []) as $capability) {
            ScannerCapability::query()->updateOrCreate(
                [
                    'technology_key' => $capability['technology_key'],
                    'scanner_key' => $capability['scanner_key'],
                    'template_group' => $capability['template_group'],
                    'scan_module' => $capability['scan_module'],
                ],
                [
                    'min_confidence' => $capability['min_confidence'],
                    'min_version' => $capability['min_version'] ?? null,
                    'max_version' => $capability['max_version'] ?? null,
                    'supported_versions' => $capability['supported_versions'] ?? null,
                    'enabled' => $capability['enabled'],
                    'safe_default' => $capability['safe_default'],
                    'priority' => $capability['priority'] ?? 50,
                    'estimated_duration_seconds' => $capability['estimated_duration_seconds'] ?? 60,
                    'estimated_requests' => $capability['estimated_requests'] ?? 20,
                    'estimated_cpu' => $capability['estimated_cpu'] ?? 0.10,
                    'estimated_memory_mb' => $capability['estimated_memory_mb'] ?? 128,
                    'safe_mode' => $capability['safe_mode'] ?? true,
                    'description' => $capability['description'],
                ]
            );
        }
    }
}
