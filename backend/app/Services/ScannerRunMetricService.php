<?php

namespace App\Services;

use App\Models\ScannerMetric;
use Illuminate\Support\Carbon;

class ScannerRunMetricService
{
    public function record(string $scannerKey, string $status, int $runtimeMs, int $findingCount): ScannerMetric
    {
        $metric = ScannerMetric::query()->firstOrCreate(
            ['scanner_key' => $scannerKey],
            [
                'runs' => 0,
                'success' => 0,
                'failed' => 0,
                'timeout' => 0,
                'avg_runtime' => 0,
                'avg_findings' => 0,
            ],
        );

        $runs = (int) $metric->runs + 1;
        $success = (int) $metric->success + ($status === 'success' ? 1 : 0);
        $failed = (int) $metric->failed + ($status === 'failed' ? 1 : 0);
        $timeout = (int) $metric->timeout + ($status === 'timeout' ? 1 : 0);

        $metric->forceFill([
            'runs' => $runs,
            'success' => $success,
            'failed' => $failed,
            'timeout' => $timeout,
            'avg_runtime' => round((((float) $metric->avg_runtime * ($runs - 1)) + $runtimeMs) / $runs, 2),
            'avg_findings' => round((((float) $metric->avg_findings * ($runs - 1)) + $findingCount) / $runs, 2),
            'last_run_at' => Carbon::now(),
        ])->save();

        return $metric->fresh();
    }
}
