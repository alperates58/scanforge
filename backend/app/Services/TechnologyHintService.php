<?php

namespace App\Services;

use App\Models\AssetDiscovery;
use App\Models\HttpObservation;
use App\Models\Website;

class TechnologyHintService
{
    public function __construct(private readonly TechnologyFingerprintEngine $fingerprintEngine)
    {
    }

    /**
     * @param list<array<string, mixed>> $cookies
     */
    public function detect(Website $website, AssetDiscovery $discovery, HttpObservation $observation, array $cookies, string $bodySample): int
    {
        $result = $this->fingerprintEngine->run($website, $discovery, $bodySample);

        return count($result['technologies'] ?? []);
    }
}
