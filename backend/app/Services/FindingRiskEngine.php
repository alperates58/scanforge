<?php

namespace App\Services;

use App\Models\CveReference;
use App\Models\Finding;
use App\Models\Website;
use App\Support\FindingSeverities;
use Illuminate\Support\Carbon;

class FindingRiskEngine
{
    /**
     * @param array<string, mixed> $normalized
     * @return array{risk_score: int, priority: string, recommended_action: string, sla_due_at: Carbon|null, inputs: array<string, mixed>}
     */
    public function calculate(array $normalized, Website $website, ?Finding $existing = null): array
    {
        $severity = (string) ($normalized['severity'] ?? $existing?->severity ?? FindingSeverities::INFO);
        $confidence = $this->boundedInt($normalized['confidence_score'] ?? $existing?->confidence_score ?? 50);
        $cvss = $this->nullableFloat($normalized['cvss_score'] ?? $normalized['cvss'] ?? $existing?->cvss_score ?? $existing?->cvss);
        $falsePositiveRisk = (string) ($normalized['false_positive_risk'] ?? $existing?->false_positive_risk ?? 'medium');
        $authenticationRequired = (bool) ($normalized['authentication_required'] ?? data_get($existing?->metadata, 'authentication_required', false));
        $internetExposed = (bool) ($normalized['internet_exposed'] ?? true);
        $cves = $this->stringList($normalized['cve_json'] ?? $normalized['cves'] ?? $existing?->cve_json ?? $existing?->cve ?? []);
        $kev = $this->hasKev($cves);

        $severityScore = $this->severityScore($severity);
        $exploitability = $this->boundedInt($normalized['exploitability'] ?? ($cvss !== null ? $cvss * 10 : $severityScore));
        $exposure = $internetExposed ? 95 : 35;
        $assetImportance = $this->assetImportanceScore((string) $website->importance);
        $cvssScore = $cvss === null ? $severityScore : (int) round($cvss * 10);
        $falsePositivePenalty = $this->falsePositivePenalty($falsePositiveRisk);
        $authPenalty = $authenticationRequired ? 8 : 0;
        $kevBonus = $kev ? 10 : 0;

        $risk = (int) round(
            ($severityScore * 0.35)
            + ($confidence * 0.15)
            + ($exploitability * 0.15)
            + ($exposure * 0.12)
            + ($assetImportance * 0.10)
            + ($cvssScore * 0.10)
            + $kevBonus
            - $falsePositivePenalty
            - $authPenalty
        );
        $risk = $this->boundedInt($risk);
        $priority = $this->priorityFor($risk);

        return [
            'risk_score' => $risk,
            'priority' => $priority,
            'recommended_action' => $this->recommendedAction($priority),
            'sla_due_at' => $this->slaDueAt($priority),
            'inputs' => [
                'severity_score' => $severityScore,
                'confidence' => $confidence,
                'exploitability' => $exploitability,
                'exposure' => $exposure,
                'asset_importance' => $assetImportance,
                'cvss_score' => $cvssScore,
                'kev' => $kev,
                'false_positive_penalty' => $falsePositivePenalty,
                'authentication_required_penalty' => $authPenalty,
            ],
        ];
    }

    public function falsePositiveRisk(int $confidenceScore, string $severity): string
    {
        if ($confidenceScore < 55) {
            return 'high';
        }

        if ($confidenceScore < 78 || $severity === FindingSeverities::INFO) {
            return 'medium';
        }

        return 'low';
    }

    private function severityScore(string $severity): int
    {
        return match ($severity) {
            FindingSeverities::CRITICAL => 100,
            FindingSeverities::HIGH => 82,
            FindingSeverities::MEDIUM => 58,
            FindingSeverities::LOW => 28,
            default => 8,
        };
    }

    private function assetImportanceScore(string $importance): int
    {
        return match ($importance) {
            'critical' => 100,
            'high' => 82,
            'low' => 25,
            default => 55,
        };
    }

    private function falsePositivePenalty(string $risk): int
    {
        return match ($risk) {
            'high' => 22,
            'low' => 0,
            default => 10,
        };
    }

    private function priorityFor(int $risk): string
    {
        return match (true) {
            $risk >= 85 => 'critical',
            $risk >= 70 => 'high',
            $risk >= 40 => 'medium',
            $risk >= 15 => 'low',
            default => 'info',
        };
    }

    private function recommendedAction(string $priority): string
    {
        return match ($priority) {
            'critical' => 'Fix immediately and verify remediation with a follow-up scan.',
            'high' => 'Prioritize remediation in the current security sprint.',
            'medium' => 'Schedule remediation and monitor for repeated occurrences.',
            'low' => 'Track as hardening work unless business context raises impact.',
            default => 'Keep for analyst context; no urgent remediation required.',
        };
    }

    private function slaDueAt(string $priority): ?Carbon
    {
        $days = config("finding_correlation.risk.sla_days.{$priority}");

        return is_numeric($days) ? Carbon::now()->addDays((int) $days) : null;
    }

    /**
     * @param list<string> $cves
     */
    private function hasKev(array $cves): bool
    {
        if ($cves === []) {
            return false;
        }

        return CveReference::query()
            ->whereIn('cve', $cves)
            ->where('kev', true)
            ->exists();
    }

    private function boundedInt(mixed $value): int
    {
        return max(0, min(100, (int) round((float) $value)));
    }

    private function nullableFloat(mixed $value): ?float
    {
        if ($value === null || $value === '') {
            return null;
        }

        return is_numeric($value) ? (float) $value : null;
    }

    /**
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        if (is_string($value)) {
            return array_values(array_filter(array_map('trim', preg_split('/[,;]/', $value) ?: [])));
        }

        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter(array_map(
            static fn (mixed $item): string => trim((string) $item),
            $value,
        )));
    }
}
