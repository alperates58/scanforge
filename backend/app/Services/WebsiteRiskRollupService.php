<?php

namespace App\Services;

use App\Models\Finding;
use App\Models\Website;
use App\Support\FindingStatuses;

class WebsiteRiskRollupService
{
    public function refresh(Website|int $website): void
    {
        $website = $website instanceof Website ? $website->fresh() : Website::query()->find($website);

        if (! $website) {
            return;
        }

        $activeStatuses = FindingStatuses::active();
        $baseQuery = Finding::query()
            ->where('website_id', $website->id)
            ->whereIn('status', $activeStatuses);

        $topRisk = (int) ((clone $baseQuery)->max('risk_score') ?? 0);
        $averageTopTen = (clone $baseQuery)
            ->orderByDesc('risk_score')
            ->limit(10)
            ->pluck('risk_score')
            ->avg();
        $averageTopTen = $averageTopTen === null ? 0 : (float) $averageTopTen;
        $newRisk = (float) round(($topRisk * 0.6) + ($averageTopTen * 0.4), 2);
        $oldRisk = (float) ($website->risk_score ?? 0);

        $cmsAsset = \App\Models\CmsAsset::query()
            ->where('website_id', $website->id)
            ->whereNotNull('cms_name')
            ->first();

        $website->forceFill([
            'risk_score' => $newRisk,
            'critical_count' => (clone $baseQuery)
                ->where(function ($query): void {
                    $query->where('priority', 'critical')->orWhere('severity', 'critical');
                })
                ->count(),
            'high_count' => (clone $baseQuery)
                ->where(function ($query): void {
                    $query->where('priority', 'high')->orWhere('severity', 'high');
                })
                ->count(),
            'risk_trend' => $this->trend($oldRisk, $newRisk),
            'cms_detected' => $cmsAsset !== null,
            'cms_name' => $cmsAsset?->cms_name,
            'cms_version' => $cmsAsset?->detected_version,
            'cms_confidence' => $cmsAsset ? ($cmsAsset->confidence === 'exact' ? 100 : ($cmsAsset->confidence === 'probable' ? 80 : 50)) : 0,
        ])->save();
    }

    private function trend(float $oldRisk, float $newRisk): string
    {
        if ($newRisk > $oldRisk + 1) {
            return 'up';
        }

        if ($newRisk < $oldRisk - 1) {
            return 'down';
        }

        return 'flat';
    }
}
