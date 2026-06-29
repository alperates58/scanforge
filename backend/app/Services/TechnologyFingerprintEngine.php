<?php

namespace App\Services;

use App\Events\CoverageUpdated;
use App\Events\FingerprintCompleted;
use App\Events\TechnologyChanged;
use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\PluginRegistry;
use App\Fingerprinting\Support\RuleEvaluator;
use App\Models\AssetDiscovery;
use App\Models\TechnologyConflict;
use App\Models\TechnologyFingerprint;
use App\Models\TechnologyRelationship;
use App\Models\Website;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

class TechnologyFingerprintEngine
{
    public function __construct(private readonly PluginRegistry $pluginRegistry)
    {
    }

    /**
     * @return array<string, mixed>
     */
    public function run(Website $website, ?AssetDiscovery $assetDiscovery = null, string $bodySample = ''): array
    {
        if (! $website->isVerified()) {
            throw new AuthorizationException('Technology fingerprinting requires a verified website.');
        }

        $context = FingerprintContext::from($website, $assetDiscovery, $bodySample);
        $evaluator = new RuleEvaluator(config('fingerprinting.source_priorities', []));
        $results = [];

        foreach ($this->pluginRegistry->ruleGroups() as $group) {
            $result = $evaluator->evaluate($group, $context);

            if ($result !== null && $result['confidence_score'] >= 30) {
                $results[$result['technology_key']] = $result;
            }
        }

        return DB::transaction(function () use ($website, $context, $results): array {
            $now = Carbon::now();
            $technologyKeys = array_keys($results);
            $existing = TechnologyFingerprint::query()
                ->where('website_id', $website->id)
                ->whereIn('technology_key', $technologyKeys)
                ->get()
                ->keyBy('technology_key');

            $rows = [];
            $changeRows = [];

            foreach ($results as $result) {
                $previous = $existing->get($result['technology_key']);
                $metadata = [
                    'phase' => 'phase04',
                    'engine' => 'plugin-rule-engine',
                    'coverage_category' => $result['coverage_category'],
                    'parents' => $result['parents'],
                    'conflicts_with' => $result['conflicts_with'],
                    'conflict_group' => $result['conflict_group'],
                ];

                $rows[] = [
                    'workspace_id' => $website->workspace_id,
                    'website_id' => $website->id,
                    'scan_id' => null,
                    'asset_discovery_id' => $context->assetDiscovery?->id,
                    'technology_key' => $result['technology_key'],
                    'technology_name' => $result['technology_name'],
                    'name' => $result['name'],
                    'category' => $result['category'],
                    'version' => $result['version'],
                    'cpe' => data_get($result, 'cpe_candidates.0.cpe'),
                    'cpe_candidates' => json_encode($result['cpe_candidates']),
                    'confidence' => round(((int) $result['confidence_score']) / 100, 3),
                    'confidence_score' => $result['confidence_score'],
                    'quality_score' => $result['quality_score'],
                    'source' => 'fingerprint_engine',
                    'detection_source' => 'rule_engine',
                    'evidence' => json_encode([
                        'evidence_count' => count($result['evidence']),
                        'sources' => array_values(array_unique(array_map(fn (array $item): string => (string) $item['source_type'], $result['evidence']))),
                        'asset_discovery_id' => $context->assetDiscovery?->id,
                    ]),
                    'metadata' => json_encode($metadata),
                    'scanner_recommendations' => json_encode([]),
                    'analysis_required' => true,
                    'analysis_version' => config('fingerprinting.analysis_version', 'fingerprint-v1'),
                    'is_active' => true,
                    'first_detected_at' => $previous?->first_detected_at ?? $now,
                    'last_detected_at' => $now,
                    'fingerprint_hash' => $this->fingerprintHash($website->id, $result),
                    'created_at' => $previous?->created_at ?? $now,
                    'updated_at' => $now,
                ];

                if ($previous && ($previous->version !== $result['version'] || (int) $previous->confidence_score !== (int) $result['confidence_score'])) {
                    $changeRows[] = [
                        'workspace_id' => $website->workspace_id,
                        'website_id' => $website->id,
                        'fingerprint_id' => $previous->id,
                        'technology_key' => $result['technology_key'],
                        'old_version' => $previous->version,
                        'new_version' => $result['version'],
                        'confidence_old' => $previous->confidence_score,
                        'confidence_new' => $result['confidence_score'],
                        'metadata' => json_encode(['reason' => 'fingerprint_recomputed']),
                        'detected_at' => $now,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ];
                }
            }

            if ($rows !== []) {
                TechnologyFingerprint::query()->upsert(
                    $rows,
                    ['website_id', 'technology_key'],
                    [
                        'workspace_id',
                        'scan_id',
                        'asset_discovery_id',
                        'technology_name',
                        'name',
                        'category',
                        'version',
                        'cpe',
                        'cpe_candidates',
                        'confidence',
                        'confidence_score',
                        'quality_score',
                        'source',
                        'detection_source',
                        'evidence',
                        'metadata',
                        'scanner_recommendations',
                        'analysis_required',
                        'analysis_version',
                        'is_active',
                        'last_detected_at',
                        'fingerprint_hash',
                        'updated_at',
                    ],
                );
            }

            $fingerprints = TechnologyFingerprint::query()
                ->where('website_id', $website->id)
                ->whereIn('technology_key', $technologyKeys)
                ->get()
                ->keyBy('technology_key');

            $this->insertEvidence($website, $context->assetDiscovery, $results, $fingerprints, $now);
            $this->insertHistories($changeRows, $fingerprints);
            $relationships = $this->refreshRelationships($website, $results, $fingerprints, $now);
            $conflicts = $this->refreshConflicts($website, $results, $fingerprints, $now);
            $coverage = $this->coverageFromResults($results);

            $website->forceFill([
                'metadata' => [
                    ...(is_array($website->metadata) ? $website->metadata : []),
                    'technology_coverage' => $coverage,
                    'technology_fingerprint_updated_at' => $now->toISOString(),
                ],
            ])->save();

            FingerprintCompleted::dispatch($website->fresh(), $context->assetDiscovery, [
                'technologies_detected' => count($results),
                'evidence_created' => array_sum(array_map(fn (array $result): int => count($result['evidence']), $results)),
                'coverage' => $coverage,
            ]);
            CoverageUpdated::dispatch($website->fresh(), $coverage);

            if ($changeRows !== []) {
                TechnologyChanged::dispatch($website->fresh(), $changeRows);
            }

            return [
                'website_id' => $website->id,
                'asset_discovery_id' => $context->assetDiscovery?->id,
                'technologies' => $fingerprints->values()->map(fn (TechnologyFingerprint $fingerprint): array => $this->fingerprintData($fingerprint))->all(),
                'coverage' => $coverage,
                'relationships' => $relationships,
                'conflicts' => $conflicts,
            ];
        });
    }

    /**
     * @return array<string, mixed>
     */
    public function summary(Website $website): array
    {
        $fingerprints = TechnologyFingerprint::query()
            ->where('website_id', $website->id)
            ->whereNotNull('technology_key')
            ->where('is_active', true)
            ->with(['evidences' => fn ($query) => $query->latest('detected_at')->limit(8)])
            ->orderByDesc('confidence_score')
            ->get();

        return [
            'technologies' => $fingerprints->map(fn (TechnologyFingerprint $fingerprint): array => $this->fingerprintData($fingerprint, includeEvidence: true))->values()->all(),
            'coverage' => $this->coverage($website),
            'relationships' => $this->relationships($website),
            'conflicts' => $this->conflicts($website),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function coverage(Website $website): array
    {
        $metadataCoverage = data_get($website->metadata, 'technology_coverage');

        if (is_array($metadataCoverage)) {
            return $metadataCoverage;
        }

        $fingerprints = TechnologyFingerprint::query()
            ->where('website_id', $website->id)
            ->where('is_active', true)
            ->whereNotNull('technology_key')
            ->get()
            ->map(fn (TechnologyFingerprint $fingerprint): array => [
                'coverage_category' => data_get($fingerprint->metadata, 'coverage_category', $fingerprint->category),
            ])
            ->all();

        return $this->coverageFromResults($fingerprints);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function relationships(Website $website): array
    {
        return TechnologyRelationship::query()
            ->where('website_id', $website->id)
            ->with(['parentFingerprint', 'childFingerprint'])
            ->get()
            ->map(fn (TechnologyRelationship $relationship): array => [
                'parent' => $relationship->parent_technology_key,
                'child' => $relationship->child_technology_key,
                'type' => $relationship->relationship_type,
                'confidence' => $relationship->confidence,
                'parent_name' => $relationship->parentFingerprint?->name,
                'child_name' => $relationship->childFingerprint?->name,
            ])
            ->values()
            ->all();
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function conflicts(Website $website): array
    {
        return TechnologyConflict::query()
            ->where('website_id', $website->id)
            ->where('status', 'open')
            ->with(['leftFingerprint', 'rightFingerprint'])
            ->get()
            ->map(fn (TechnologyConflict $conflict): array => [
                'category' => $conflict->category,
                'severity' => $conflict->severity,
                'reason' => $conflict->reason,
                'left' => $conflict->leftFingerprint?->name,
                'right' => $conflict->rightFingerprint?->name,
                'detected_at' => $conflict->detected_at?->toISOString(),
            ])
            ->values()
            ->all();
    }

    /**
     * @param array<string, mixed> $result
     */
    private function fingerprintHash(int $websiteId, array $result): string
    {
        return hash('sha256', implode('|', [
            $websiteId,
            $result['technology_key'],
            $result['version'] ?? 'unknown',
            $result['confidence_score'],
            $result['quality_score'],
        ]));
    }

    /**
     * @param array<string, array<string, mixed>> $results
     */
    private function insertEvidence(Website $website, ?AssetDiscovery $assetDiscovery, array $results, $fingerprints, Carbon $now): void
    {
        $rows = [];

        foreach ($results as $technologyKey => $result) {
            $fingerprint = $fingerprints->get($technologyKey);

            if (! $fingerprint) {
                continue;
            }

            foreach ($result['evidence'] as $evidence) {
                $rows[] = [
                    'workspace_id' => $website->workspace_id,
                    'website_id' => $website->id,
                    'fingerprint_id' => $fingerprint->id,
                    'asset_discovery_id' => $assetDiscovery?->id,
                    'source_type' => $evidence['source_type'],
                    'source_key' => $evidence['source_key'],
                    'source_value' => $evidence['source_value'],
                    'confidence' => $evidence['confidence'],
                    'raw_data' => json_encode($evidence['raw_data']),
                    'detected_at' => $now,
                    'created_at' => $now,
                    'updated_at' => $now,
                ];
            }
        }

        if ($rows !== []) {
            DB::table('technology_evidences')->insert($rows);
        }
    }

    /**
     * @param list<array<string, mixed>> $changeRows
     */
    private function insertHistories(array $changeRows, $fingerprints): void
    {
        if ($changeRows === []) {
            return;
        }

        $rows = [];

        foreach ($changeRows as $row) {
            $fingerprint = $fingerprints->get($row['technology_key']);
            $row['fingerprint_id'] = $fingerprint?->id ?? $row['fingerprint_id'];
            $rows[] = $row;
        }

        DB::table('fingerprint_histories')->insert($rows);
    }

    /**
     * @param array<string, array<string, mixed>> $results
     * @return list<array<string, mixed>>
     */
    private function refreshRelationships(Website $website, array $results, $fingerprints, Carbon $now): array
    {
        TechnologyRelationship::query()->where('website_id', $website->id)->delete();

        $rows = [];

        foreach ($results as $childKey => $result) {
            $childFingerprint = $fingerprints->get($childKey);

            foreach ($result['parents'] as $parentKey) {
                $parentFingerprint = $fingerprints->get($parentKey);

                if (! $parentFingerprint || ! $childFingerprint || $parentKey === $childKey) {
                    continue;
                }

                $rows[] = [
                    'workspace_id' => $website->workspace_id,
                    'website_id' => $website->id,
                    'parent_fingerprint_id' => $parentFingerprint->id,
                    'child_fingerprint_id' => $childFingerprint->id,
                    'parent_technology_key' => $parentKey,
                    'child_technology_key' => $childKey,
                    'relationship_type' => 'supports',
                    'confidence' => min((int) $parentFingerprint->confidence_score, (int) $childFingerprint->confidence_score),
                    'metadata' => json_encode(['source' => 'rule_group_parent']),
                    'detected_at' => $now,
                    'created_at' => $now,
                    'updated_at' => $now,
                ];
            }
        }

        if ($rows !== []) {
            DB::table('technology_relationships')->insert($rows);
        }

        return array_map(fn (array $row): array => [
            'parent' => $row['parent_technology_key'],
            'child' => $row['child_technology_key'],
            'type' => $row['relationship_type'],
            'confidence' => $row['confidence'],
        ], $rows);
    }

    /**
     * @param array<string, array<string, mixed>> $results
     * @return list<array<string, mixed>>
     */
    private function refreshConflicts(Website $website, array $results, $fingerprints, Carbon $now): array
    {
        TechnologyConflict::query()->where('website_id', $website->id)->delete();

        $threshold = (int) config('fingerprinting.conflict_threshold', 75);
        $rows = [];
        $grouped = [];

        foreach ($results as $key => $result) {
            if (($result['conflict_group'] ?? null) && $result['confidence_score'] >= $threshold) {
                $grouped[$result['conflict_group']][$key] = $result;
            }
        }

        foreach ($grouped as $group => $items) {
            $keys = array_keys($items);

            for ($i = 0; $i < count($keys); $i++) {
                for ($j = $i + 1; $j < count($keys); $j++) {
                    $left = $fingerprints->get($keys[$i]);
                    $right = $fingerprints->get($keys[$j]);

                    if (! $left || ! $right) {
                        continue;
                    }

                    $rows[] = [
                        'workspace_id' => $website->workspace_id,
                        'website_id' => $website->id,
                        'left_fingerprint_id' => $left->id,
                        'right_fingerprint_id' => $right->id,
                        'category' => $group,
                        'severity' => 'medium',
                        'reason' => sprintf('%s and %s both have high confidence in an exclusive technology group.', $left->name, $right->name),
                        'status' => 'open',
                        'detected_at' => $now,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ];
                }
            }
        }

        if ($rows !== []) {
            DB::table('technology_conflicts')->insert($rows);
        }

        return array_map(fn (array $row): array => [
            'category' => $row['category'],
            'severity' => $row['severity'],
            'reason' => $row['reason'],
        ], $rows);
    }

    /**
     * @param array<int|string, array<string, mixed>> $results
     * @return array<string, mixed>
     */
    private function coverageFromResults(array $results): array
    {
        $categories = config('fingerprinting.coverage_categories', []);
        $present = [];

        foreach ($results as $result) {
            $category = $result['coverage_category'] ?? $result['category'] ?? null;

            if ($category) {
                $present[$category] = true;
            }
        }

        $items = [];

        foreach ($categories as $category) {
            $items[$category] = [
                'present' => isset($present[$category]),
                'label' => str_replace('_', ' ', $category),
            ];
        }

        $percentage = count($categories) === 0 ? 0 : (int) round((count($present) / count($categories)) * 100);

        return [
            'percentage' => min(100, $percentage),
            'covered' => count($present),
            'total' => count($categories),
            'items' => $items,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function fingerprintData(TechnologyFingerprint $fingerprint, bool $includeEvidence = false): array
    {
        $data = [
            'id' => $fingerprint->id,
            'technology_key' => $fingerprint->technology_key,
            'name' => $fingerprint->name,
            'category' => $fingerprint->category,
            'version' => $fingerprint->version,
            'confidence_score' => $fingerprint->confidence_score,
            'quality_score' => $fingerprint->quality_score,
            'cpe_candidates' => $fingerprint->cpe_candidates ?? [],
            'analysis_required' => $fingerprint->analysis_required,
            'analysis_version' => $fingerprint->analysis_version,
            'metadata' => $fingerprint->metadata,
            'last_detected_at' => $fingerprint->last_detected_at?->toISOString(),
        ];

        if ($includeEvidence) {
            $data['evidence'] = $fingerprint->evidences->map(fn ($evidence): array => [
                'source_type' => $evidence->source_type,
                'source_key' => $evidence->source_key,
                'source_value' => $evidence->source_value,
                'confidence' => $evidence->confidence,
                'raw_data' => $evidence->raw_data,
                'detected_at' => $evidence->detected_at?->toISOString(),
            ])->values()->all();
        }

        return $data;
    }
}
