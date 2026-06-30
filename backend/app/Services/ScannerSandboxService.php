<?php

namespace App\Services;

use App\Models\ScanJob;
use App\Scanners\Support\ScannerSandbox;
use Illuminate\Support\Facades\File;

class ScannerSandboxService
{
    public function prepare(ScanJob $scanJob): ScannerSandbox
    {
        $jobUuid = $scanJob->job_uuid ?: (string) str()->uuid();

        if ($scanJob->job_uuid === null) {
            $scanJob->forceFill(['job_uuid' => $jobUuid])->save();
        }

        $root = rtrim((string) config('nuclei.sandbox_root', '/tmp/scanforge'), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$jobUuid;
        $sandbox = new ScannerSandbox(
            root: $root,
            workingDirectory: $root.DIRECTORY_SEPARATOR.'work',
            tempDirectory: $root.DIRECTORY_SEPARATOR.'tmp',
            outputDirectory: $root.DIRECTORY_SEPARATOR.'output',
        );

        foreach ([$sandbox->root, $sandbox->workingDirectory, $sandbox->tempDirectory, $sandbox->outputDirectory] as $directory) {
            File::ensureDirectoryExists($directory, 0700, true);
        }

        return $sandbox;
    }

    public function cleanup(ScannerSandbox $sandbox): void
    {
        if (str_contains($sandbox->root, '..')) {
            return;
        }

        File::deleteDirectory($sandbox->root);
    }
}
