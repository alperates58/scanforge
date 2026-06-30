<?php

namespace App\Services;

use App\Models\Finding;
use App\Models\FindingDelta;
use App\Models\FindingSource;
use App\Models\Scan;
use App\Models\ScanJob;
use Illuminate\Support\Carbon;

class FindingDeltaService
{
    public function recordObserved(
        Finding $finding,
        ?int $previousScanId,
        ?string $oldSeverity,
        ?int $oldRiskScore,
        bool $created,
    ): void {
        if ($finding->scan_id === null) {
            return;
        }

        $deltaType = 'unchanged';

        if ($created || $previousScanId === null) {
            $deltaType = 'new';
        } elseif ($oldRiskScore !== null && (int) $finding->risk_score > $oldRiskScore) {
            $deltaType = 'worsened';
        }

        FindingDelta::query()->create([
            'workspace_id' => $finding->workspace_id,
            'website_id' => $finding->website_id,
            'scan_id' => $finding->scan_id,
            'previous_scan_id' => $previousScanId,
            'finding_id' => $finding->id,
            'delta_type' => $deltaType,
            'old_status' => null,
            'new_status' => $finding->status,
            'old_score' => $oldRiskScore,
            'new_score' => $finding->risk_score,
            'old_severity' => $oldSeverity,
            'new_severity' => $finding->severity,
            'reason' => $created ? 'Finding first observed in this scan.' : 'Finding observed again in this scan.',
            'metadata' => [
                'correlation_key' => $finding->correlation_key,
                'template_id' => $finding->template_id,
            ],
            'calculated_at' => Carbon::now(),
        ]);
    }

    public function recordResolvedForScan(Scan $scan): void
    {
        $previousScan = Scan::query()
            ->where('website_id', $scan->website_id)
            ->where('id', '<', $scan->id)
            ->latest('id')
            ->first();

        if (! $previousScan) {
            return;
        }

        $currentJobIds = ScanJob::query()->where('scan_id', $scan->id)->pluck('id')->all();
        $previousJobIds = ScanJob::query()->where('scan_id', $previousScan->id)->pluck('id')->all();

        $currentFindingIds = FindingSource::query()
            ->where('website_id', $scan->website_id)
            ->whereIn('scan_job_id', $currentJobIds)
            ->pluck('finding_id')
            ->unique()
            ->all();

        $previousFindingIds = FindingSource::query()
            ->where('website_id', $scan->website_id)
            ->whereIn('scan_job_id', $previousJobIds)
            ->pluck('finding_id')
            ->unique()
            ->all();

        $resolvedIds = array_values(array_diff($previousFindingIds, $currentFindingIds));

        foreach ($resolvedIds as $findingId) {
            $finding = Finding::query()->find($findingId);

            if (! $finding) {
                continue;
            }

            FindingDelta::query()->firstOrCreate(
                [
                    'scan_id' => $scan->id,
                    'finding_id' => $finding->id,
                    'delta_type' => 'resolved',
                ],
                [
                    'workspace_id' => $scan->workspace_id,
                    'website_id' => $scan->website_id,
                    'previous_scan_id' => $previousScan->id,
                    'old_status' => $finding->status,
                    'new_status' => 'resolved_candidate',
                    'old_score' => $finding->risk_score,
                    'new_score' => 0,
                    'old_severity' => $finding->severity,
                    'new_severity' => null,
                    'reason' => 'Finding was present in the previous scan but not observed in this scan.',
                    'metadata' => [
                        'correlation_key' => $finding->correlation_key,
                    ],
                    'calculated_at' => Carbon::now(),
                ],
            );
        }
    }
}
