<?php

namespace App\Events;

use App\Models\Website;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class TechnologyChanged
{
    use Dispatchable;
    use SerializesModels;

    /**
     * @param list<array<string, mixed>> $changes
     */
    public function __construct(
        public readonly Website $website,
        public readonly array $changes,
    ) {
    }
}
