<?php

namespace App\Scanners\Native;

use App\Models\ScanJob;
use App\Scanners\Cms\CmsPluginRegistry;
use App\Services\ArtifactManifestService;
use App\Services\FindingNormalizationService;
use App\Services\ScanJobLifecycleService;
use App\Services\ScanProgressService;

class CmsScannerAdapter extends AbstractNativeScanner
{
    public function __construct(
        ScanJobLifecycleService $scanJobLifecycleService,
        ScanProgressService $scanProgressService,
        FindingNormalizationService $findingNormalizationService,
        ArtifactManifestService $artifactManifestService,
        private readonly CmsPluginRegistry $cmsPluginRegistry
    ) {
        parent::__construct(
            $scanJobLifecycleService,
            $scanProgressService,
            $findingNormalizationService,
            $artifactManifestService
        );
    }

    public function scannerKey(): string
    {
        return 'cms_scanner';
    }

    protected function performChecks(ScanJob $scanJob): array
    {
        $pluginKey = $scanJob->scan_module; // Use scan_module to determine plugin (e.g. 'wordpress_cms')
        
        $plugin = $this->cmsPluginRegistry->get($pluginKey);
        
        if (! $plugin) {
            return [
                $this->createErrorPayload('unknown_cms_plugin', "Unknown CMS Plugin: {$pluginKey}"),
            ];
        }

        $results = $plugin->performChecks($scanJob);
        return $results;
    }

    private function createErrorPayload(string $checkId, string $description): array
    {
        return [
            'check_id' => $checkId,
            'severity' => 'info',
            'title' => 'CMS Scanner Configuration Error',
            'description' => $description,
            'cwe' => null,
            'affected_url' => '',
            'evidence' => [],
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
