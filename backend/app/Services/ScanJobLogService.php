<?php

namespace App\Services;

use App\Models\ScanJob;
use App\Models\ScanJobLog;
use Illuminate\Support\Carbon;

class ScanJobLogService
{
    /**
     * @param array<string, mixed> $context
     */
    public function record(ScanJob $scanJob, string $level, string $message, array $context = []): ScanJobLog
    {
        return ScanJobLog::query()->create([
            'scan_job_id' => $scanJob->id,
            'scan_id' => $scanJob->scan_id,
            'workspace_id' => $scanJob->workspace_id,
            'timestamp' => Carbon::now(),
            'level' => $level,
            'message' => $message,
            'context' => $this->redact($context),
        ]);
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    private function redact(array $context): array
    {
        $sensitiveFragments = ['password', 'secret', 'token', 'cookie', 'authorization', 'api_key'];

        foreach ($context as $key => $value) {
            $lowerKey = strtolower((string) $key);

            foreach ($sensitiveFragments as $fragment) {
                if (str_contains($lowerKey, $fragment)) {
                    $context[$key] = '[redacted]';
                    continue 2;
                }
            }

            if (is_array($value)) {
                $context[$key] = $this->redact($value);
            }
        }

        return $context;
    }
}
