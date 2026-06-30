<?php

namespace App\Services;

use App\Models\CanonicalFinding;
use App\Models\ConfidenceHistory;
use App\Models\CveReference;
use App\Models\Finding;
use App\Models\FindingEvidence;
use App\Models\FindingSource;
use App\Models\FindingTaxonomy;
use App\Models\RiskScoreHistory;
use App\Models\SuppressionRule;
use App\Models\Website;
use App\Support\FindingStatuses;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

class FindingCorrelationService
{
    public function __construct(
        private readonly FindingRiskEngine $findingRiskEngine,
        private readonly FindingStatusTransitionService $findingStatusTransitionService,
        private readonly WebsiteRiskRollupService $websiteRiskRollupService,
        private readonly FindingDeltaService $findingDeltaService,
    ) {
    }

    /**
     * @param array<string, mixed> $normalized
     */
    public function persist(Website $website, array $normalized): Finding
    {
        $finding = DB::transaction(function () use ($website, $normalized): Finding {
            $now = Carbon::now();
            $taxonomy = $this->taxonomy($normalized['taxonomy'] ?? []);
            $canonical = $this->canonicalFinding($taxonomy, $normalized);
            [$existing, $matchedRule, $matchedScore] = $this->findExisting($website, $normalized);
            $created = ! $existing;
            $oldRisk = $existing?->risk_score === null ? null : (int) $existing->risk_score;
            $oldConfidence = $existing?->confidence_score === null ? null : (int) $existing->confidence_score;
            $oldSeverity = $existing?->severity;
            $oldStatus = $existing?->status;
            $suppression = $this->matchingSuppression($website, $normalized);
            $status = $this->statusFor($existing, $suppression);
            $risk = $this->findingRiskEngine->calculate($normalized, $website, $existing);
            $correlationKey = $this->correlationKey($normalized, $matchedRule);
            $correlationScore = max($matchedScore, $this->sourceBoostedCorrelationScore($existing, $normalized));

            $finding = $existing ?: new Finding([
                'workspace_id' => $website->workspace_id,
                'website_id' => $website->id,
                'first_seen_at' => $now,
                'occurrence_count' => 0,
            ]);

            $fingerprint = $finding->fingerprint_hash ?: hash('sha256', $correlationKey);
            $dedupeHash = $finding->dedupe_hash ?: $fingerprint;

            $finding->forceFill([
                'workspace_id' => $website->workspace_id,
                'website_id' => $website->id,
                'scan_id' => $normalized['scan_id'] ?? $finding->scan_id,
                'asset_discovery_id' => $normalized['asset_discovery_id'] ?? $finding->asset_discovery_id,
                'raw_artifact_id' => $normalized['raw_artifact_id'] ?? $finding->raw_artifact_id,
                'canonical_finding_id' => $canonical->id,
                'finding_taxonomy_id' => $taxonomy?->id,
                'asset_type' => $normalized['asset_type'] ?? null,
                'asset_id' => $normalized['asset_id'] ?? null,
                'asset_identifier' => $normalized['asset_identifier'] ?? null,
                'title' => $normalized['title'],
                'normalized_title' => $normalized['normalized_title'] ?? $normalized['title'],
                'description' => $normalized['description'] ?? null,
                'normalized_description' => $normalized['normalized_description'] ?? $normalized['description'] ?? null,
                'severity' => $normalized['severity'],
                'confidence' => $normalized['confidence'] ?? ((int) $normalized['confidence_score'] / 100),
                'confidence_score' => (int) $normalized['confidence_score'],
                'false_positive_risk' => $normalized['false_positive_risk'] ?? 'medium',
                'risk_score' => $risk['risk_score'],
                'priority' => $risk['priority'],
                'affected_url' => $normalized['affected_url'],
                'affected_component' => $normalized['affected_component'] ?? null,
                'affected_parameter' => $normalized['affected_parameter'] ?? null,
                'parameter' => $normalized['parameter'] ?? $normalized['affected_parameter'] ?? null,
                'source_tool' => $normalized['source_tool'],
                'scanner_key' => $normalized['scanner_key'],
                'template_id' => $normalized['template_id'] ?? null,
                'cwe' => $normalized['cwe'] ?? null,
                'cwe_json' => $normalized['cwe_json'] ?? [],
                'cve' => $normalized['cve'] ?? null,
                'cve_json' => $normalized['cve_json'] ?? [],
                'cvss' => $normalized['cvss'] ?? null,
                'cvss_score' => $normalized['cvss_score'] ?? $normalized['cvss'] ?? null,
                'owasp_category' => $normalized['owasp_category'] ?? $taxonomy?->owasp_category,
                'evidence' => $normalized['evidence_text'] ?? json_encode($normalized['evidence'] ?? [], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
                'evidence_json' => $normalized['evidence'] ?? null,
                'remediation' => $normalized['remediation'] ?? $canonical->default_remediation,
                'references' => $normalized['references'] ?? [],
                'fingerprint_hash' => $fingerprint,
                'dedupe_hash' => $dedupeHash,
                'correlation_key' => $correlationKey,
                'correlation_score' => $correlationScore,
                'related_finding_id' => $existing ? $existing->related_finding_id : null,
                'last_seen_at' => $normalized['observed_at'] ?? $now,
                'resolved_at' => $status === FindingStatuses::RESOLVED ? ($finding->resolved_at ?? $now) : (in_array($status, FindingStatuses::active(), true) ? null : $finding->resolved_at),
                'reopened_at' => $status === FindingStatuses::REOPENED ? $now : $finding->reopened_at,
                'occurrence_count' => ((int) $finding->occurrence_count) + 1,
                'matched_at' => $normalized['matched_at'] ?? null,
                'status' => $status,
                'analysis_required' => (bool) ($normalized['analysis_required'] ?? $status !== FindingStatuses::FALSE_POSITIVE),
                'analysis_version' => config('finding_correlation.analysis_version', 'finding-v1'),
                'analysis_status' => $normalized['analysis_status'] ?? 'pending',
                'sla_due_at' => $risk['sla_due_at'],
                'metadata' => [
                    ...(is_array($finding->metadata) ? $finding->metadata : []),
                    ...($normalized['metadata'] ?? []),
                    'recommended_action' => $risk['recommended_action'],
                    'risk_inputs' => $risk['inputs'],
                    'correlation_rule' => $matchedRule,
                    'suppression_rule_id' => $suppression?->id,
                ],
            ])->save();

            $finding = $finding->fresh();
            $this->recordSource($finding, $normalized, $now);
            $this->recordEvidence($finding, $normalized, $now);
            $this->recordCves($normalized);
            $this->recordRiskHistory($finding, $oldRisk, $risk['risk_score'], $created ? 'initial_calculation' : 'finding_recalculated', $risk['inputs']);
            $this->recordConfidenceHistory($finding, $oldConfidence, (int) $normalized['confidence_score'], $normalized);

            if ($created || $oldStatus !== $status) {
                $this->findingStatusTransitionService->recordEvent(
                    $finding,
                    $oldStatus,
                    $status,
                    $created ? 'Finding created by correlation engine.' : 'Finding status updated by correlation engine.',
                    null,
                    [
                        'scanner_key' => $normalized['scanner_key'],
                        'template_id' => $normalized['template_id'] ?? null,
                        'correlation_rule' => $matchedRule,
                    ],
                );
            }

            $this->findingDeltaService->recordObserved(
                $finding,
                $this->previousScanId($website, $normalized['scan_id'] ?? null),
                $oldSeverity,
                $oldRisk,
                $created,
            );

            return $finding;
        });

        $this->websiteRiskRollupService->refresh($website->id);

        return $finding->fresh();
    }

    /**
     * @param array<string, mixed> $normalized
     * @return array{0: Finding|null, 1: string, 2: int}
     */
    private function findExisting(Website $website, array $normalized): array
    {
        $exactHash = hash('sha256', $this->correlationKey($normalized, 'exact_template_url'));
        $exact = Finding::query()
            ->where('website_id', $website->id)
            ->where('dedupe_hash', $exactHash)
            ->first();

        if ($exact) {
            return [$exact, 'exact_template_url', 100];
        }

        if (! empty($normalized['template_id']) && ! empty($normalized['affected_url'])) {
            $finding = Finding::query()
                ->where('website_id', $website->id)
                ->where('template_id', $normalized['template_id'])
                ->where('affected_url', $normalized['affected_url'])
                ->first();

            if ($finding) {
                return [$finding, 'exact_template_url', 100];
            }
        }

        $cves = $this->stringList($normalized['cve_json'] ?? $normalized['cve'] ?? []);

        if ($cves !== []) {
            $finding = Finding::query()
                ->where('website_id', $website->id)
                ->whereIn('cve', $cves)
                ->orderByDesc('risk_score')
                ->first();

            if ($finding) {
                return [$finding, 'same_cve_host', 92];
            }
        }

        if (! empty($normalized['cwe']) && ! empty($normalized['affected_component'])) {
            $finding = Finding::query()
                ->where('website_id', $website->id)
                ->where('cwe', $normalized['cwe'])
                ->where('affected_component', $normalized['affected_component'])
                ->where(function ($query) use ($normalized): void {
                    $query
                        ->where('affected_parameter', $normalized['affected_parameter'] ?? null)
                        ->orWhereNull('affected_parameter');
                })
                ->first();

            if ($finding) {
                return [$finding, 'same_cwe_path_parameter', 84];
            }
        }

        if (in_array($normalized['asset_type'] ?? null, ['header', 'cookie'], true) && ! empty($normalized['asset_identifier'])) {
            $finding = Finding::query()
                ->where('website_id', $website->id)
                ->where('asset_type', $normalized['asset_type'])
                ->where('asset_identifier', $normalized['asset_identifier'])
                ->where('normalized_title', $normalized['normalized_title'])
                ->first();

            if ($finding) {
                return [$finding, 'header_cookie_name', 78];
            }
        }

        if (($normalized['asset_type'] ?? null) === 'certificate' && ! empty($normalized['asset_identifier'])) {
            $finding = Finding::query()
                ->where('website_id', $website->id)
                ->where('asset_type', 'certificate')
                ->where('asset_identifier', $normalized['asset_identifier'])
                ->first();

            if ($finding) {
                return [$finding, 'ssl_certificate_host_fingerprint', 86];
            }
        }

        if (! empty($normalized['normalized_title']) && ! empty($normalized['affected_component'])) {
            $finding = Finding::query()
                ->where('website_id', $website->id)
                ->where('normalized_title', $normalized['normalized_title'])
                ->where('affected_component', $normalized['affected_component'])
                ->first();

            if ($finding) {
                return [$finding, 'same_title_component', 72];
            }
        }

        return [null, 'exact_template_url', 100];
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function statusFor(?Finding $existing, ?SuppressionRule $suppression): string
    {
        if ($suppression) {
            return $suppression->action === FindingStatuses::FALSE_POSITIVE
                ? FindingStatuses::FALSE_POSITIVE
                : FindingStatuses::IGNORED;
        }

        if (! $existing) {
            return FindingStatuses::NEW;
        }

        if (in_array($existing->status, FindingStatuses::terminal(), true)) {
            return FindingStatuses::REOPENED;
        }

        return $existing->status ?: FindingStatuses::NEW;
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function matchingSuppression(Website $website, array $normalized): ?SuppressionRule
    {
        $host = parse_url((string) $normalized['affected_url'], PHP_URL_HOST) ?: $website->host;

        return SuppressionRule::query()
            ->where('enabled', true)
            ->where(function ($query) use ($website): void {
                $query->whereNull('workspace_id')->orWhere('workspace_id', $website->workspace_id);
            })
            ->where(function ($query) use ($website): void {
                $query->whereNull('website_id')->orWhere('website_id', $website->id);
            })
            ->where(function ($query) use ($normalized): void {
                $query->whereNull('scanner_key')->orWhere('scanner_key', $normalized['scanner_key']);
            })
            ->where(function ($query) use ($normalized): void {
                $query->whereNull('template_id')->orWhere('template_id', $normalized['template_id'] ?? null);
            })
            ->where(function ($query) use ($host): void {
                $query->whereNull('host')->orWhere('host', $host);
            })
            ->where(function ($query): void {
                $query->whereNull('expires_at')->orWhere('expires_at', '>', Carbon::now());
            })
            ->latest()
            ->first();
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function taxonomy(array $taxonomy): ?FindingTaxonomy
    {
        if ($taxonomy === []) {
            return null;
        }

        return FindingTaxonomy::query()->firstOrCreate(
            [
                'category' => $taxonomy['category'] ?? 'Security Misconfiguration',
                'subcategory' => $taxonomy['subcategory'] ?? null,
                'owasp_category' => $taxonomy['owasp_category'] ?? null,
                'cwe' => $taxonomy['cwe'] ?? null,
            ],
            [
                'asvs_control' => $taxonomy['asvs_control'] ?? null,
                'capec' => $taxonomy['capec'] ?? null,
                'metadata' => [],
            ],
        );
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function canonicalFinding(?FindingTaxonomy $taxonomy, array $normalized): CanonicalFinding
    {
        return CanonicalFinding::query()->firstOrCreate(
            ['normalized_key' => $normalized['canonical_key']],
            [
                'finding_taxonomy_id' => $taxonomy?->id,
                'default_title' => $normalized['title'],
                'default_description' => $normalized['description'] ?? null,
                'default_remediation' => $normalized['remediation'] ?? null,
                'default_references' => $normalized['references'] ?? [],
                'ai_summary_template' => '{{title}} was observed on {{asset}} with {{severity}} severity and {{confidence}} confidence.',
                'metadata' => [
                    'source' => $normalized['scanner_key'],
                ],
            ],
        );
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function correlationKey(array $normalized, string $rule): string
    {
        $host = parse_url((string) ($normalized['affected_url'] ?? ''), PHP_URL_HOST) ?: '';

        return match ($rule) {
            'same_cve_host' => implode('|', ['cve', implode(',', $this->stringList($normalized['cve_json'] ?? [])), $host]),
            'same_cwe_path_parameter' => implode('|', ['cwe', $normalized['cwe'] ?? '', $normalized['affected_component'] ?? '', $normalized['affected_parameter'] ?? '']),
            'same_title_component' => implode('|', ['title', $normalized['normalized_title'] ?? '', $normalized['affected_component'] ?? '']),
            'header_cookie_name' => implode('|', ['asset', $normalized['asset_type'] ?? '', $normalized['asset_identifier'] ?? '', $normalized['normalized_title'] ?? '']),
            'ssl_certificate_host_fingerprint' => implode('|', ['ssl', $host, $normalized['asset_identifier'] ?? '']),
            default => implode('|', ['template', $normalized['template_id'] ?? '', $normalized['affected_url'] ?? '', $normalized['affected_parameter'] ?? '']),
        };
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function sourceBoostedCorrelationScore(?Finding $existing, array $normalized): int
    {
        if (! $existing) {
            return 100;
        }

        $scannerCount = FindingSource::query()
            ->where('finding_id', $existing->id)
            ->distinct('scanner_key')
            ->count('scanner_key');

        $scannerBonus = $scannerCount > 0 && ! FindingSource::query()
            ->where('finding_id', $existing->id)
            ->where('scanner_key', $normalized['scanner_key'])
            ->exists()
            ? 10
            : 0;

        return min(100, (int) $existing->correlation_score + $scannerBonus);
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function recordSource(Finding $finding, array $normalized, Carbon $observedAt): void
    {
        FindingSource::query()->create([
            'finding_id' => $finding->id,
            'workspace_id' => $finding->workspace_id,
            'website_id' => $finding->website_id,
            'scanner_key' => $normalized['scanner_key'],
            'scan_job_id' => $normalized['scan_job_id'] ?? null,
            'raw_artifact_id' => $normalized['raw_artifact_id'] ?? null,
            'template_id' => $normalized['template_id'] ?? null,
            'source_severity' => $normalized['severity'] ?? null,
            'source_confidence' => $normalized['confidence_score'] ?? null,
            'source_payload' => $normalized['source_payload'] ?? null,
            'observed_at' => $normalized['observed_at'] ?? $observedAt,
        ]);
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function recordEvidence(Finding $finding, array $normalized, Carbon $observedAt): void
    {
        $payload = $normalized['evidence'] ?? [];
        $encoded = is_string($payload) ? $payload : json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        FindingEvidence::query()->firstOrCreate(
            [
                'finding_id' => $finding->id,
                'sha256' => hash('sha256', $encoded),
            ],
            [
                'workspace_id' => $finding->workspace_id,
                'website_id' => $finding->website_id,
                'type' => $normalized['asset_type'] ?? 'scanner_result',
                'mime' => 'application/json',
                'artifact_id' => $normalized['raw_artifact_id'] ?? null,
                'thumbnail' => null,
                'preview' => mb_substr($encoded, 0, 1200),
                'metadata' => [
                    'scanner_key' => $normalized['scanner_key'],
                    'template_id' => $normalized['template_id'] ?? null,
                ],
                'observed_at' => $normalized['observed_at'] ?? $observedAt,
            ],
        );
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function recordCves(array $normalized): void
    {
        foreach ($this->stringList($normalized['cve_json'] ?? []) as $cve) {
            CveReference::query()->firstOrCreate(
                ['cve' => $cve],
                ['cvss' => $normalized['cvss_score'] ?? $normalized['cvss'] ?? null],
            );
        }
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function recordRiskHistory(Finding $finding, ?int $oldScore, int $newScore, string $reason, array $metadata): void
    {
        if ($oldScore !== null && $oldScore === $newScore) {
            return;
        }

        RiskScoreHistory::query()->create([
            'finding_id' => $finding->id,
            'workspace_id' => $finding->workspace_id,
            'website_id' => $finding->website_id,
            'old_score' => $oldScore,
            'new_score' => $newScore,
            'reason' => $reason,
            'metadata' => $metadata,
            'calculated_at' => Carbon::now(),
        ]);
    }

    /**
     * @param array<string, mixed> $normalized
     */
    private function recordConfidenceHistory(Finding $finding, ?int $oldConfidence, int $newConfidence, array $normalized): void
    {
        if ($oldConfidence !== null && $oldConfidence === $newConfidence) {
            return;
        }

        ConfidenceHistory::query()->create([
            'finding_id' => $finding->id,
            'workspace_id' => $finding->workspace_id,
            'website_id' => $finding->website_id,
            'confidence' => $newConfidence,
            'reason' => $oldConfidence === null ? 'initial_confidence' : 'confidence_recalculated',
            'scanner' => $normalized['scanner_key'],
            'metadata' => [
                'old_confidence' => $oldConfidence,
                'template_id' => $normalized['template_id'] ?? null,
            ],
            'calculated_at' => Carbon::now(),
        ]);
    }

    private function previousScanId(Website $website, mixed $scanId): ?int
    {
        if (! is_numeric($scanId)) {
            return null;
        }

        $previous = DB::table('scans')
            ->where('website_id', $website->id)
            ->where('id', '<', (int) $scanId)
            ->orderByDesc('id')
            ->value('id');

        return is_numeric($previous) ? (int) $previous : null;
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
