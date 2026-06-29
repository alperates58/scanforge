<?php

namespace App\Services;

use App\Models\ScannerCapability;
use App\Models\TechnologyFingerprint;
use Illuminate\Support\Collection;

class CapabilityResolver
{
    /**
     * @param Collection<int, TechnologyFingerprint> $fingerprints
     * @return array<int, list<array<string, mixed>>>
     */
    public function resolveForFingerprints(Collection $fingerprints): array
    {
        $technologyKeys = $fingerprints->pluck('technology_key')->filter()->unique()->values()->all();
        $dbCapabilities = ScannerCapability::query()
            ->whereIn('technology_key', $technologyKeys)
            ->where('enabled', true)
            ->get()
            ->groupBy('technology_key');

        $configCapabilities = collect(config('scanner_capabilities', []))
            ->whereIn('technology_key', $technologyKeys)
            ->where('enabled', true)
            ->groupBy('technology_key');

        $resolved = [];

        foreach ($fingerprints as $fingerprint) {
            $capabilities = $dbCapabilities->get($fingerprint->technology_key);

            if (! $capabilities || $capabilities->isEmpty()) {
                $capabilities = collect($configCapabilities->get($fingerprint->technology_key, []));
            }

            $resolved[$fingerprint->id] = $capabilities
                ->map(fn ($capability): array => $this->normalize($capability))
                ->filter(fn (array $capability): bool => $this->isEligible($fingerprint, $capability))
                ->map(fn (array $capability): array => [
                    ...$capability,
                    'technology_fingerprint_id' => $fingerprint->id,
                    'technology_key' => $fingerprint->technology_key,
                    'recommendation_score' => $this->recommendationScore($fingerprint, $capability),
                    'reason' => sprintf(
                        '%s matched %s at %d%% confidence with %d%% evidence quality.',
                        $fingerprint->name,
                        $capability['scanner_key'],
                        $fingerprint->confidence_score,
                        $fingerprint->quality_score,
                    ),
                ])
                ->sortByDesc('recommendation_score')
                ->values()
                ->all();
        }

        return $resolved;
    }

    /**
     * @param ScannerCapability|array<string, mixed> $capability
     * @return array<string, mixed>
     */
    private function normalize(ScannerCapability|array $capability): array
    {
        if ($capability instanceof ScannerCapability) {
            return [
                'technology_key' => $capability->technology_key,
                'scanner_key' => $capability->scanner_key,
                'template_group' => $capability->template_group,
                'scan_module' => $capability->scan_module,
                'min_confidence' => $capability->min_confidence,
                'min_version' => $capability->min_version,
                'max_version' => $capability->max_version,
                'supported_versions' => $capability->supported_versions,
                'safe_default' => $capability->safe_default,
                'priority' => $capability->priority,
                'estimated_duration_seconds' => $capability->estimated_duration_seconds,
                'estimated_requests' => $capability->estimated_requests,
                'estimated_cpu' => $capability->estimated_cpu,
                'estimated_memory_mb' => $capability->estimated_memory_mb,
                'safe_mode' => $capability->safe_mode,
                'description' => $capability->description,
            ];
        }

        return [
            'technology_key' => $capability['technology_key'],
            'scanner_key' => $capability['scanner_key'],
            'template_group' => $capability['template_group'],
            'scan_module' => $capability['scan_module'],
            'min_confidence' => $capability['min_confidence'] ?? 70,
            'min_version' => $capability['min_version'] ?? null,
            'max_version' => $capability['max_version'] ?? null,
            'supported_versions' => $capability['supported_versions'] ?? null,
            'safe_default' => $capability['safe_default'] ?? true,
            'priority' => $capability['priority'] ?? 50,
            'estimated_duration_seconds' => $capability['estimated_duration_seconds'] ?? 60,
            'estimated_requests' => $capability['estimated_requests'] ?? 20,
            'estimated_cpu' => $capability['estimated_cpu'] ?? 0.10,
            'estimated_memory_mb' => $capability['estimated_memory_mb'] ?? 128,
            'safe_mode' => $capability['safe_mode'] ?? true,
            'description' => $capability['description'] ?? null,
        ];
    }

    /**
     * @param array<string, mixed> $capability
     */
    private function isEligible(TechnologyFingerprint $fingerprint, array $capability): bool
    {
        if ($fingerprint->confidence_score < $capability['min_confidence']) {
            return false;
        }

        if (! $fingerprint->version) {
            return true;
        }

        if ($capability['min_version'] && version_compare($fingerprint->version, $capability['min_version'], '<')) {
            return false;
        }

        if ($capability['max_version'] && version_compare($fingerprint->version, $capability['max_version'], '>')) {
            return false;
        }

        if (is_array($capability['supported_versions']) && $capability['supported_versions'] !== []) {
            foreach ($capability['supported_versions'] as $supportedVersion) {
                $prefix = rtrim((string) $supportedVersion, 'x.*');

                if ($prefix !== '' && str_starts_with($fingerprint->version, $prefix)) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    /**
     * @param array<string, mixed> $capability
     */
    private function recommendationScore(TechnologyFingerprint $fingerprint, array $capability): int
    {
        return min(100, (int) round(
            ($fingerprint->confidence_score * 0.40)
            + ($fingerprint->quality_score * 0.25)
            + ($capability['priority'] * 0.25)
            + (($capability['safe_mode'] && $capability['safe_default']) ? 10 : 0),
        ));
    }
}
