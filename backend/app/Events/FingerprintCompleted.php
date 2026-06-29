<?php

namespace App\Events;

use App\Models\AssetDiscovery;
use App\Models\Website;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class FingerprintCompleted
{
    use Dispatchable;
    use SerializesModels;

    /**
     * @param array<string, mixed> $summary
     */
    public function __construct(
        public readonly Website $website,
        public readonly ?AssetDiscovery $assetDiscovery,
        public readonly array $summary,
    ) {
    }
}
