<?php

namespace App\Jobs;

use App\Services\ScannerExecutorService;
use Illuminate\Bus\Batchable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class ExecuteScanJob implements ShouldQueue
{
    use Batchable;
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 1;

    public function __construct(public readonly int $scanJobId)
    {
    }

    public function handle(ScannerExecutorService $scannerExecutorService): void
    {
        if ($this->batch()?->cancelled()) {
            return;
        }

        $scannerExecutorService->execute($this->scanJobId);
    }

    public function backoff(): int
    {
        return (int) config('scanforge.retry.default.backoff_seconds', 30);
    }
}
