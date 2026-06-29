<?php

namespace App\Services;

use App\Models\CookieObservation;
use App\Models\HttpObservation;
use App\Models\ScanPlan;
use App\Models\SslCertificate;
use App\Models\TechnologyFingerprint;
use App\Models\TechnologyRelationship;
use App\Models\Website;

class TechnologyGraphExporter
{
    /**
     * @return array<string, mixed>
     */
    public function export(Website $website): array
    {
        $technologies = TechnologyFingerprint::query()
            ->where('website_id', $website->id)
            ->where('is_active', true)
            ->whereNotNull('technology_key')
            ->orderByDesc('confidence_score')
            ->get();

        $relationships = TechnologyRelationship::query()
            ->where('website_id', $website->id)
            ->get();

        $latestHttp = HttpObservation::query()->where('website_id', $website->id)->latest('observed_at')->first();
        $latestSsl = SslCertificate::query()->where('website_id', $website->id)->latest('observed_at')->first();
        $latestPlan = ScanPlan::query()->where('website_id', $website->id)->with('items')->latest('generated_at')->first();

        return [
            'website' => [
                'id' => $website->id,
                'host' => $website->host,
                'environment' => $website->environment,
                'importance' => $website->importance,
                'verification_status' => $website->verification_status,
            ],
            'asset_graph' => [
                'host' => $website->host,
                'ssl' => [
                    'available' => (bool) data_get($latestSsl?->tls_summary, 'available', false),
                    'issuer' => $latestSsl?->issuer,
                    'days_remaining' => $latestSsl?->days_remaining,
                ],
                'headers' => $latestHttp?->headers ?? [],
                'cookies' => CookieObservation::query()
                    ->where('website_id', $website->id)
                    ->latest('observed_at')
                    ->limit(20)
                    ->pluck('name')
                    ->values()
                    ->all(),
            ],
            'technologies' => $technologies->map(fn (TechnologyFingerprint $fingerprint): array => [
                'id' => $fingerprint->id,
                'key' => $fingerprint->technology_key,
                'name' => $fingerprint->name,
                'category' => $fingerprint->category,
                'version' => $fingerprint->version,
                'confidence_score' => $fingerprint->confidence_score,
                'quality_score' => $fingerprint->quality_score,
                'analysis_required' => $fingerprint->analysis_required,
                'analysis_version' => $fingerprint->analysis_version,
            ])->values()->all(),
            'relationships' => $relationships->map(fn (TechnologyRelationship $relationship): array => [
                'from' => $relationship->parent_technology_key,
                'to' => $relationship->child_technology_key,
                'type' => $relationship->relationship_type,
                'confidence' => $relationship->confidence,
            ])->values()->all(),
            'latest_scan_plan' => $latestPlan ? [
                'id' => $latestPlan->id,
                'coverage_prediction' => $latestPlan->coverage_prediction,
                'estimated_runtime_seconds' => $latestPlan->estimated_runtime_seconds,
                'estimated_requests' => $latestPlan->estimated_requests,
                'estimated_cpu' => $latestPlan->estimated_cpu,
                'estimated_memory_mb' => $latestPlan->estimated_memory_mb,
                'items' => $latestPlan->items->count(),
            ] : null,
        ];
    }
}
