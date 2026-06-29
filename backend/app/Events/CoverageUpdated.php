<?php

namespace App\Events;

use App\Models\Website;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class CoverageUpdated
{
    use Dispatchable;
    use SerializesModels;

    /**
     * @param array<string, mixed> $coverage
     */
    public function __construct(
        public readonly Website $website,
        public readonly array $coverage,
    ) {
    }
}
