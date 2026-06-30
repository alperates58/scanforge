<?php

namespace Database\Seeders;

use App\Models\TemplateManifest;
use Illuminate\Database\Seeder;

class TemplateManifestSeeder extends Seeder
{
    public function run(): void
    {
        foreach (config('nuclei.template_manifest', []) as $template) {
            TemplateManifest::query()->updateOrCreate(
                [
                    'scanner_key' => 'nuclei',
                    'template_id' => $template['template_id'],
                ],
                [
                    'group' => $template['group'] ?? null,
                    'severity' => $template['severity'] ?? 'info',
                    'tags' => $template['tags'] ?? [],
                    'author' => $template['author'] ?? null,
                    'signed' => (bool) ($template['signed'] ?? false),
                    'last_updated' => $template['last_updated'] ?? null,
                    'deprecated' => (bool) ($template['deprecated'] ?? false),
                    'metadata' => $template['metadata'] ?? ['source' => 'phase06_seed'],
                ],
            );
        }
    }
}
