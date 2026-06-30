<?php

namespace App\Services;

use App\Models\Finding;
use App\Models\RawArtifact;
use App\Models\ScanJob;

class NucleiFindingNormalizer
{
    public function __construct(
        private readonly FindingNormalizationService $findingNormalizationService,
    ) {
    }

    /**
     * @return list<Finding>
     */
    public function persistFindings(ScanJob $scanJob, RawArtifact $rawArtifact, string $jsonl): array
    {
        return $this->findingNormalizationService->persistNucleiJsonl($scanJob, $rawArtifact, $jsonl);
    }
}
