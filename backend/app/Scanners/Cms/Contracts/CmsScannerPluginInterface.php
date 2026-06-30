<?php

namespace App\Scanners\Cms\Contracts;

use App\Models\ScanJob;

interface CmsScannerPluginInterface
{
    /**
     * Unique key for this CMS plugin (e.g., 'wordpress_cms', 'generic_cms').
     */
    public function key(): string;

    /**
     * Perform the CMS-specific checks based on existing observation data.
     * Must return an array of finding payloads.
     *
     * @return array<int, array<string, mixed>>
     */
    public function performChecks(ScanJob $scanJob): array;
}
