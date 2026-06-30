<?php

namespace App\Scanners\Cms\Plugins;

use App\Models\HttpObservation;
use App\Models\ScanJob;
use App\Scanners\Cms\Contracts\CmsScannerPluginInterface;
use Illuminate\Support\Carbon;

class GenericCmsPlugin implements CmsScannerPluginInterface
{
    public function key(): string
    {
        return 'generic_cms';
    }

    public function performChecks(ScanJob $scanJob): array
    {
        $findings = [];
        $websiteId = $scanJob->website_id;
        $affectedUrl = $scanJob->website?->url ?? 'http://' . ($scanJob->website?->host ?? 'unknown');

        // Look for generator meta tag in HTTP observations
        $generatorObservations = HttpObservation::query()
            ->where('website_id', $websiteId)
            ->whereNotNull('generator_meta')
            ->get();

        foreach ($generatorObservations as $obs) {
            $tagContent = $obs->generator_meta;
            if (!empty($tagContent)) {
                $findings[] = $this->createPayload(
                    'generic_generator_exposed',
                    'info',
                    'CMS Generator Exposed',
                    "CMS generator information is exposed: {$tagContent}",
                    'CWE-200',
                    $affectedUrl,
                    ['meta_tag' => $tagContent],
                    $tagContent
                );
            }
        }

        return $findings;
    }

    private function createPayload(string $checkId, string $severity, string $title, string $description, string $cwe, string $affectedUrl, array $evidence, string $cmsName = null): array
    {
        $payload = [
            'check_id' => $checkId,
            'severity' => $severity,
            'title' => $title,
            'description' => $description,
            'cwe' => $cwe,
            'affected_url' => $affectedUrl,
            'evidence' => $evidence,
            'timestamp' => Carbon::now()->toIso8601String(),
        ];

        if ($cmsName) {
            $payload['cms_name'] = $cmsName;
            $payload['detection_sources'] = ['generator_meta'];
        }

        return $payload;
    }
}
