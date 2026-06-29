<?php

namespace App\Events;

use App\Models\ScanJob;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class JobCancelled
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(public readonly ScanJob $scanJob)
    {
    }
}
