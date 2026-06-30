<?php

namespace App\Services;

use App\Models\ArtifactManifest;
use App\Models\RawArtifact;

class ArtifactManifestService
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function record(
        RawArtifact $rawArtifact,
        string $content,
        string $mime = 'application/jsonl',
        bool $compressed = false,
        string $retentionPolicy = 'scan_raw_default',
        array $metadata = [],
    ): ArtifactManifest {
        return ArtifactManifest::query()->updateOrCreate(
            ['raw_artifact_id' => $rawArtifact->id],
            [
                'checksum' => hash('sha256', $content),
                'size' => strlen($content),
                'mime' => $mime,
                'compressed' => $compressed,
                'retention_policy' => $retentionPolicy,
                'metadata' => $metadata,
            ],
        );
    }
}
