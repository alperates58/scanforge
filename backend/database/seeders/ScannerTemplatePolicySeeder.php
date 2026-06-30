<?php

namespace Database\Seeders;

use App\Models\ScannerTemplatePolicy;
use Illuminate\Database\Seeder;

class ScannerTemplatePolicySeeder extends Seeder
{
    public function run(): void
    {
        foreach (config('nuclei.policies', []) as $policy) {
            ScannerTemplatePolicy::query()->updateOrCreate(
                [
                    'scanner_key' => 'nuclei',
                    'template_group' => $policy['template_group'],
                ],
                [
                    'allowed' => (bool) ($policy['allowed'] ?? false),
                    'safety_level' => $policy['safety_level'] ?? 'safe',
                    'blocked_tags' => $policy['blocked_tags'] ?? config('nuclei.blocked_template_tags', []),
                    'allowed_tags' => $policy['allowed_tags'] ?? config('nuclei.safe_template_tags', []),
                    'reason' => $policy['reason'] ?? null,
                ],
            );
        }
    }
}
