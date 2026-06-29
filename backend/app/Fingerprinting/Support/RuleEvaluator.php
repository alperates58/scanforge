<?php

namespace App\Fingerprinting\Support;

class RuleEvaluator
{
    /**
     * @param array<string, int> $sourcePriorities
     */
    public function __construct(private readonly array $sourcePriorities)
    {
    }

    /**
     * @return array<string, mixed>|null
     */
    public function evaluate(RuleGroup $group, FingerprintContext $context): ?array
    {
        $evidence = [];
        $weightedScore = 0;
        $maxWeighted = 0;
        $version = null;

        foreach ($group->rules as $rule) {
            $result = $rule->evaluate($context);

            if ($result === null) {
                continue;
            }

            $priority = $this->sourcePriorities[strtolower((string) $result['source_type'])] ?? 50;
            $result['source_priority'] = $priority;
            $result['weighted_confidence'] = (int) round(((int) $result['confidence']) * ($priority / 100));

            $weightedScore += $result['weighted_confidence'];
            $maxWeighted = max($maxWeighted, $result['weighted_confidence']);
            $version ??= $result['version'];
            $evidence[] = $result;
        }

        if ($evidence === []) {
            return null;
        }

        $confidenceScore = min(100, max($maxWeighted, (int) round($weightedScore)));
        $sourceTypes = array_unique(array_map(fn (array $item): string => (string) $item['source_type'], $evidence));
        $qualityScore = min(100, 10 + (count($evidence) * 20) + (count($sourceTypes) * 10) + ($version ? 15 : 0));

        return [
            'technology_key' => $group->technologyKey,
            'technology_name' => $group->technologyName,
            'name' => $group->technologyName,
            'category' => $group->category,
            'coverage_category' => $group->coverageCategory ?? $group->category,
            'version' => $version,
            'confidence_score' => $confidenceScore,
            'quality_score' => $qualityScore,
            'evidence' => $evidence,
            'parents' => $group->parents,
            'conflicts_with' => $group->conflictsWith,
            'conflict_group' => $group->conflictGroup,
            'cpe_candidates' => $this->cpeCandidates($group, $version, $confidenceScore, $evidence),
        ];
    }

    /**
     * @param list<array<string, mixed>> $evidence
     * @return list<array<string, mixed>>
     */
    private function cpeCandidates(RuleGroup $group, ?string $version, int $confidenceScore, array $evidence): array
    {
        if ($group->cpeVendor === null || $group->cpeProduct === null || $version === null) {
            return [];
        }

        $source = $evidence[0]['source_type'] ?? 'unknown';

        return [[
            'confidence' => max(0, min(100, $confidenceScore - 5)),
            'source' => $source,
            'cpe' => sprintf('cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*:*', $group->cpeVendor, $group->cpeProduct, $version),
            'version' => $version,
        ]];
    }
}
