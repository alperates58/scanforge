<?php

namespace App\Events;

use App\Models\ScanPlan;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ScanPlanGenerated
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(public readonly ScanPlan $scanPlan)
    {
    }
}
