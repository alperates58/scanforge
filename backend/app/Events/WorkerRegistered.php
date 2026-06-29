<?php

namespace App\Events;

use App\Models\Worker;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class WorkerRegistered
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(public readonly Worker $worker)
    {
    }
}
