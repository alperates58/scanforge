<?php

namespace App\Services;

use App\Models\ScannerVersion;
use Illuminate\Support\Carbon;

class ScannerVersionService
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function record(string $scannerKey, ?string $binaryVersion, ?string $templatesVersion, string $status, array $metadata = []): ScannerVersion
    {
        return ScannerVersion::query()->updateOrCreate(
            ['scanner_key' => $scannerKey],
            [
                'binary_version' => $binaryVersion,
                'templates_version' => $templatesVersion,
                'last_checked_at' => Carbon::now(),
                'status' => $status,
                'metadata' => $metadata,
            ],
        );
    }
}
