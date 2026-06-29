<?php

namespace App\Services;

use App\Events\ScanPlanGenerated;
use App\Models\AssetDiscovery;
use App\Models\ScanPlan;
use App\Models\ScanPlanItem;
use App\Models\TechnologyFingerprint;
use App\Models\Website;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

class ScanPlanService
{
    public function __construct(private readonly CapabilityResolver $capabilityResolver)
    {
    }

    /**
     * @return array<string, mixed>
     */
    public function generate(Website $website): array
    {
        $fingerprints = TechnologyFingerprint::query()
            ->where('website_id', $website->id)
            ->where('is_active', true)
            ->whereNotNull('technology_key')
            ->orderByDesc('confidence_score')
            ->get();

        $resolved = $this->capabilityResolver->resolveForFingerprints($fingerprints);
        $items = collect($resolved)->flatten(1)->sortByDesc('recommendation_score')->values();
        $now = Carbon::now();
        $latestDiscovery = AssetDiscovery::query()->where('website_id', $website->id)->latest('completed_at')->first();
        $coveredFingerprintIds = $items->pluck('technology_fingerprint_id')->unique()->count();
        $coveragePrediction = $fingerprints->count() === 0 ? 0 : (int) round(($coveredFingerprintIds / $fingerprints->count()) * 100);

        $plan = DB::transaction(function () use ($website, $latestDiscovery, $items, $now, $coveragePrediction): ScanPlan {
            $plan = ScanPlan::query()->create([
                'workspace_id' => $website->workspace_id,
                'website_id' => $website->id,
                'asset_discovery_id' => $latestDiscovery?->id,
                'status' => 'ready',
                'coverage_prediction' => $coveragePrediction,
                'estimated_runtime_seconds' => $items->sum('estimated_duration_seconds'),
                'estimated_requests' => $items->sum('estimated_requests'),
                'estimated_cpu' => round((float) $items->sum('estimated_cpu'), 2),
                'estimated_memory_mb' => (int) ($items->max('estimated_memory_mb') ?? 0),
                'safe_mode' => $items->every(fn (array $item): bool => (bool) $item['safe_mode']),
                'analysis_required' => true,
                'generated_from' => 'technology_fingerprinting',
                'summary' => [
                    'items' => $items->count(),
                    'safe_default_items' => $items->where('safe_default', true)->count(),
                    'phase' => 'phase04',
                ],
                'generated_at' => $now,
            ]);

            if ($items->isNotEmpty()) {
                DB::table('scan_plan_items')->insert($items->map(fn (array $item): array => [
                    'scan_plan_id' => $plan->id,
                    'technology_fingerprint_id' => $item['technology_fingerprint_id'],
                    'technology_key' => $item['technology_key'],
                    'scanner_key' => $item['scanner_key'],
                    'template_group' => $item['template_group'],
                    'scan_module' => $item['scan_module'],
                    'priority' => $item['priority'],
                    'recommendation_score' => $item['recommendation_score'],
                    'estimated_duration_seconds' => $item['estimated_duration_seconds'],
                    'estimated_requests' => $item['estimated_requests'],
                    'estimated_cpu' => $item['estimated_cpu'],
                    'estimated_memory_mb' => $item['estimated_memory_mb'],
                    'safe_mode' => $item['safe_mode'],
                    'reason' => $item['reason'],
                    'metadata' => json_encode([
                        'description' => $item['description'],
                        'safe_default' => $item['safe_default'],
                        'min_confidence' => $item['min_confidence'],
                        'min_version' => $item['min_version'],
                        'max_version' => $item['max_version'],
                        'supported_versions' => $item['supported_versions'],
                    ]),
                    'created_at' => $now,
                    'updated_at' => $now,
                ])->all());

                $groupedRecommendations = $items->groupBy('technology_fingerprint_id');

                foreach ($groupedRecommendations as $fingerprintId => $recommendations) {
                    TechnologyFingerprint::query()->whereKey($fingerprintId)->update([
                        'scanner_recommendations' => json_encode($recommendations->values()->all()),
                        'updated_at' => $now,
                    ]);
                }
            }

            return $plan->fresh(['items']);
        });

        $website->forceFill([
            'metadata' => [
                ...(is_array($website->metadata) ? $website->metadata : []),
                'scan_coverage_prediction' => $coveragePrediction,
                'latest_scan_plan_id' => $plan->id,
            ],
        ])->save();

        ScanPlanGenerated::dispatch($plan);

        return $this->planData($plan);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function list(Website $website): array
    {
        return ScanPlan::query()
            ->where('website_id', $website->id)
            ->with('items')
            ->latest('generated_at')
            ->limit(20)
            ->get()
            ->map(fn (ScanPlan $plan): array => $this->planData($plan))
            ->values()
            ->all();
    }

    /**
     * @return array<string, mixed>
     */
    public function planData(ScanPlan $plan): array
    {
        $plan->loadMissing('items');

        return [
            'id' => $plan->id,
            'website_id' => $plan->website_id,
            'asset_discovery_id' => $plan->asset_discovery_id,
            'status' => $plan->status,
            'coverage_prediction' => $plan->coverage_prediction,
            'estimated_runtime_seconds' => $plan->estimated_runtime_seconds,
            'estimated_requests' => $plan->estimated_requests,
            'estimated_cpu' => $plan->estimated_cpu,
            'estimated_memory_mb' => $plan->estimated_memory_mb,
            'safe_mode' => $plan->safe_mode,
            'analysis_required' => $plan->analysis_required,
            'summary' => $plan->summary,
            'generated_at' => $plan->generated_at?->toISOString(),
            'items' => $plan->items->map(fn (ScanPlanItem $item): array => [
                'id' => $item->id,
                'technology_key' => $item->technology_key,
                'scanner_key' => $item->scanner_key,
                'template_group' => $item->template_group,
                'scan_module' => $item->scan_module,
                'priority' => $item->priority,
                'recommendation_score' => $item->recommendation_score,
                'estimated_duration_seconds' => $item->estimated_duration_seconds,
                'estimated_requests' => $item->estimated_requests,
                'estimated_cpu' => $item->estimated_cpu,
                'estimated_memory_mb' => $item->estimated_memory_mb,
                'safe_mode' => $item->safe_mode,
                'reason' => $item->reason,
                'metadata' => $item->metadata,
            ])->values()->all(),
        ];
    }
}
