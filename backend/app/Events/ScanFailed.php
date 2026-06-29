<?php

namespace App\Events;

use App\Models\Scan;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ScanFailed
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(public readonly Scan $scan)
    {
    }
}
