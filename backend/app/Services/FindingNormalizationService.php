<?php

namespace App\Services;

use App\Models\AssetDiscovery;
use App\Models\Finding;
use App\Models\RawArtifact;
use App\Models\ScanJob;
use App\Models\Website;
use App\Support\FindingSeverities;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

class FindingNormalizationService
{
    public function __construct(
        private readonly FindingCorrelationService $findingCorrelationService,
        private readonly FindingRiskEngine $findingRiskEngine,
    ) {
    }

    /**
     * @return list<Finding>
     */
    public function persistNucleiJsonl(ScanJob $scanJob, RawArtifact $rawArtifact, string $jsonl): array
    {
        $findings = [];
        $lines = preg_split('/\r\n|\r|\n/', trim($jsonl));

        foreach ($lines === false ? [] : $lines as $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            $payload = json_decode($line, true);

            if (! is_array($payload)) {
                continue;
            }

            $finding = $this->persistNucleiPayload($scanJob, $rawArtifact, $payload);

            if ($finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function persistNucleiPayload(ScanJob $scanJob, RawArtifact $rawArtifact, array $payload): ?Finding
    {
        $scanJob->loadMissing(['website']);
        $website = $scanJob->website;

        if (! $website instanceof Website) {
            return null;
        }

        $info = data_get($payload, 'info', []);
        $info = is_array($info) ? $info : [];
        $templateId = (string) ($payload['template-id'] ?? $payload['template_id'] ?? $payload['template'] ?? 'unknown-template');
        $affectedUrl = (string) ($payload['matched-at'] ?? $payload['matched_at'] ?? $payload['host'] ?? $website->url ?? '');

        if ($affectedUrl === '') {
            return null;
        }

        $severity = $this->severity((string) ($info['severity'] ?? 'info'));
        $parameter = $this->nullableString($payload['matcher-name'] ?? $payload['matcher_name'] ?? $payload['parameter'] ?? null);
        $references = $this->stringList($info['reference'] ?? $info['references'] ?? []);
        $cves = $this->stringList(data_get($info, 'classification.cve-id', data_get($payload, 'classification.cve-id', [])));
        $cwes = $this->stringList(data_get($info, 'classification.cwe-id', data_get($payload, 'classification.cwe-id', [])));
        $cvss = $this->nullableFloat(data_get($info, 'classification.cvss-score', data_get($payload, 'classification.cvss-score')));
        $confidenceScore = $this->confidenceForScanner('nuclei', $severity, $cvss);
        $path = $this->pathFromUrl($affectedUrl);
        $matchedAt = $this->parseDate($payload['timestamp'] ?? $payload['matched_at'] ?? null);
        $evidence = [
            'template_id' => $templateId,
            'matched_at' => $affectedUrl,
            'matcher_name' => $parameter,
            'extracted_results' => $payload['extracted-results'] ?? $payload['extracted_results'] ?? null,
            'type' => $payload['type'] ?? null,
            'ip' => $payload['ip'] ?? null,
            'template_url' => $payload['template-url'] ?? null,
        ];
        $title = (string) ($info['name'] ?? $templateId);
        $taxonomy = $this->taxonomyFor($cwes, $title, null);

        return $this->findingCorrelationService->persist($website, [
            'workspace_id' => $website->workspace_id,
            'scan_id' => $scanJob->scan_id,
            'scan_job_id' => $scanJob->id,
            'raw_artifact_id' => $rawArtifact->id,
            'scanner_key' => 'nuclei',
            'source_tool' => 'nuclei',
            'template_id' => $templateId,
            'title' => $title,
            'normalized_title' => $this->normalizeText($title),
            'description' => $this->nullableString($info['description'] ?? null),
            'normalized_description' => $this->nullableString($info['description'] ?? null),
            'severity' => $severity,
            'confidence' => $confidenceScore / 100,
            'confidence_score' => $confidenceScore,
            'false_positive_risk' => $this->findingRiskEngine->falsePositiveRisk($confidenceScore, $severity),
            'affected_url' => $affectedUrl,
            'affected_component' => $path,
            'affected_parameter' => $parameter,
            'parameter' => $parameter,
            'asset_type' => 'url',
            'asset_identifier' => $affectedUrl,
            'cve' => $cves[0] ?? null,
            'cve_json' => $cves,
            'cwe' => $cwes[0] ?? $taxonomy['cwe'] ?? null,
            'cwe_json' => $cwes,
            'cvss' => $cvss,
            'cvss_score' => $cvss,
            'owasp_category' => $taxonomy['owasp_category'],
            'taxonomy' => $taxonomy,
            'evidence' => $evidence,
            'evidence_text' => json_encode($evidence, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            'remediation' => $this->nullableString($info['remediation'] ?? null),
            'references' => $references,
            'matched_at' => $matchedAt,
            'observed_at' => $matchedAt ?? Carbon::now(),
            'source_payload' => $this->redact($payload),
            'canonical_key' => $this->canonicalKey($templateId, $title, $cves, $cwes),
            'internet_exposed' => true,
            'authentication_required' => false,
            'metadata' => [
                'scanner_key' => 'nuclei',
                'template_group' => $scanJob->template_group,
                'scan_module' => $scanJob->scan_module,
                'all_cves' => $cves,
                'all_cwes' => $cwes,
            ],
        ]);
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function persistNativeScannerFinding(ScanJob $scanJob, RawArtifact $rawArtifact, array $payload): ?Finding
    {
        $scanJob->loadMissing(['website']);
        $website = $scanJob->website;

        if (! $website instanceof Website) {
            return null;
        }

        $scannerKey = (string) ($payload['scanner_key'] ?? $scanJob->scanner_key);
        $templateId = (string) ($payload['check_id'] ?? 'unknown-check');
        $affectedUrl = (string) ($payload['affected_url'] ?? $website->url ?? '');

        if ($affectedUrl === '') {
            return null;
        }

        $severity = $this->severity((string) ($payload['severity'] ?? 'info'));
        $parameter = $this->nullableString($payload['parameter'] ?? null);
        $references = $this->stringList($payload['references'] ?? []);
        
        $confidenceScore = 80;
        $path = $this->pathFromUrl($affectedUrl);
        $matchedAt = $this->parseDate($payload['timestamp'] ?? null) ?? Carbon::now();
        
        $evidence = $payload['evidence'] ?? [];
        $title = (string) ($payload['title'] ?? $templateId);
        
        $cwe = $this->nullableString($payload['cwe'] ?? null);
        $cwes = $cwe ? [$cwe] : [];
        $taxonomy = $this->taxonomyFor($cwes, $title, null);

        return $this->findingCorrelationService->persist($website, [
            'workspace_id' => $website->workspace_id,
            'scan_id' => $scanJob->scan_id,
            'scan_job_id' => $scanJob->id,
            'raw_artifact_id' => $rawArtifact->id,
            'scanner_key' => $scannerKey,
            'source_tool' => 'scanforge-native',
            'template_id' => $templateId,
            'title' => $title,
            'normalized_title' => $this->normalizeText($title),
            'description' => $this->nullableString($payload['description'] ?? null),
            'normalized_description' => $this->nullableString($payload['description'] ?? null),
            'severity' => $severity,
            'confidence' => $confidenceScore / 100,
            'confidence_score' => $confidenceScore,
            'false_positive_risk' => $this->findingRiskEngine->falsePositiveRisk($confidenceScore, $severity),
            'affected_url' => $affectedUrl,
            'affected_component' => $payload['affected_component'] ?? $path,
            'affected_parameter' => $parameter,
            'parameter' => $parameter,
            'asset_type' => $payload['asset_type'] ?? 'url',
            'asset_identifier' => $payload['asset_identifier'] ?? $affectedUrl,
            'cve' => null,
            'cve_json' => [],
            'cwe' => $cwes[0] ?? $taxonomy['cwe'] ?? null,
            'cwe_json' => $cwes,
            'cvss' => null,
            'cvss_score' => null,
            'owasp_category' => $taxonomy['owasp_category'],
            'taxonomy' => $taxonomy,
            'evidence' => $evidence,
            'evidence_text' => is_string($evidence) ? $evidence : json_encode($evidence, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            'remediation' => $this->nullableString($payload['remediation'] ?? null),
            'references' => $references,
            'matched_at' => $matchedAt,
            'observed_at' => $matchedAt,
            'source_payload' => $this->redact($payload),
            'canonical_key' => $this->canonicalKey($templateId, $title, [], $cwes),
            'internet_exposed' => true,
            'authentication_required' => false,
            'metadata' => array_filter([
                'scanner_key' => $scannerKey,
                'template_group' => $scanJob->template_group,
                'scan_module' => $scanJob->scan_module,
                'cms_name' => $payload['cms_name'] ?? null,
                'cms_version' => $payload['cms_version'] ?? null,
                'detection_sources' => $payload['detection_sources'] ?? null,
            ]),
        ]);
    }

    /**
     * @param array{title: string, severity: string, evidence: string, remediation: string, metadata: array<string, mixed>} $data
     */
    public function persistPassiveFinding(Website $website, AssetDiscovery $discovery, array $data): Finding
    {
        $metadata = $data['metadata'];
        $category = (string) ($metadata['category'] ?? 'passive');
        $severity = $this->severity($data['severity']);
        $confidenceScore = 80;
        $asset = $this->passiveAsset($website, $metadata);
        $taxonomy = $this->taxonomyFor([], $data['title'], $category);
        $canonicalKey = 'passive:'.Str::slug($category.'-'.$data['title']);

        return $this->findingCorrelationService->persist($website, [
            'workspace_id' => $website->workspace_id,
            'scan_id' => null,
            'asset_discovery_id' => $discovery->id,
            'scanner_key' => 'passive_discovery',
            'source_tool' => 'scanforge-passive-discovery',
            'template_id' => $canonicalKey,
            'title' => $data['title'],
            'normalized_title' => $this->normalizeText($data['title']),
            'description' => null,
            'normalized_description' => null,
            'severity' => $severity,
            'confidence' => $confidenceScore / 100,
            'confidence_score' => $confidenceScore,
            'false_positive_risk' => $this->findingRiskEngine->falsePositiveRisk($confidenceScore, $severity),
            'affected_url' => $website->url,
            'affected_component' => $asset['component'],
            'affected_parameter' => $asset['parameter'],
            'parameter' => $asset['parameter'],
            'asset_type' => $asset['type'],
            'asset_id' => $asset['id'],
            'asset_identifier' => $asset['identifier'],
            'cve' => null,
            'cve_json' => [],
            'cwe' => $taxonomy['cwe'],
            'cwe_json' => array_values(array_filter([$taxonomy['cwe']])),
            'cvss' => null,
            'cvss_score' => null,
            'owasp_category' => $taxonomy['owasp_category'],
            'taxonomy' => $taxonomy,
            'evidence' => [
                'text' => $data['evidence'],
                'metadata' => $metadata,
            ],
            'evidence_text' => $data['evidence'],
            'remediation' => $data['remediation'],
            'references' => [],
            'matched_at' => Carbon::now(),
            'observed_at' => Carbon::now(),
            'source_payload' => $this->redact($metadata),
            'canonical_key' => $canonicalKey,
            'internet_exposed' => true,
            'authentication_required' => false,
            'metadata' => $metadata,
        ]);
    }

    /**
     * @param list<string> $cwes
     * @return array{category: string, subcategory: string|null, owasp_category: string|null, asvs_control: string|null, cwe: string|null, capec: string|null}
     */
    private function taxonomyFor(array $cwes, string $title, ?string $passiveCategory): array
    {
        $defaults = config('finding_taxonomy.defaults');
        $cweConfig = config('finding_taxonomy.cwe', []);
        $passiveConfig = config('finding_taxonomy.passive_categories', []);
        $primaryCwe = $cwes[0] ?? null;

        if ($primaryCwe && isset($cweConfig[$primaryCwe]) && is_array($cweConfig[$primaryCwe])) {
            return [
                ...$defaults,
                ...$cweConfig[$primaryCwe],
                'cwe' => $primaryCwe,
            ];
        }

        if ($passiveCategory && isset($passiveConfig[$passiveCategory]) && is_array($passiveConfig[$passiveCategory])) {
            return [
                ...$defaults,
                ...$passiveConfig[$passiveCategory],
            ];
        }

        if (str_contains(strtolower($title), 'sql')) {
            return [
                ...$defaults,
                ...($cweConfig['CWE-89'] ?? []),
                'cwe' => 'CWE-89',
            ];
        }

        return $defaults;
    }

    /**
     * @return array{type: string, id: int|null, identifier: string, component: string|null, parameter: string|null}
     */
    private function passiveAsset(Website $website, array $metadata): array
    {
        $category = (string) ($metadata['category'] ?? 'website');
        $identifier = $website->url;
        $type = 'website';
        $component = $website->host;
        $parameter = null;

        if ($category === 'security_headers' || $category === 'headers') {
            $type = 'header';
            $identifier = (string) ($metadata['header_key'] ?? $metadata['server_header'] ?? $metadata['powered_by_header'] ?? 'header');
            $component = $identifier;
        } elseif ($category === 'cookies') {
            $type = 'cookie';
            $identifier = (string) ($metadata['attribute'] ?? data_get($metadata, 'cookies.0.name', 'cookie'));
            $component = $identifier;
            $parameter = (string) ($metadata['attribute'] ?? '');
        } elseif ($category === 'ssl') {
            $type = 'certificate';
            $identifier = (string) ($metadata['fingerprint_sha256'] ?? $website->host);
            $component = $website->host;
        } elseif ($category === 'target_safety') {
            $type = 'host';
            $identifier = $website->host;
            $component = $website->host;
        }

        return [
            'type' => $type,
            'id' => $website->id,
            'identifier' => $identifier,
            'component' => $component,
            'parameter' => $parameter ?: null,
        ];
    }

    private function canonicalKey(string $templateId, string $title, array $cves, array $cwes): string
    {
        if ($cves !== []) {
            return 'cve:'.implode(',', array_unique($cves));
        }

        if ($templateId !== '' && $templateId !== 'unknown-template') {
            return 'template:'.Str::slug($templateId);
        }

        return 'title:'.Str::slug(($cwes[0] ?? 'general').'-'.$title);
    }

    private function confidenceForScanner(string $scannerKey, string $severity, ?float $cvss): int
    {
        $base = match ($scannerKey) {
            'nuclei' => match ($severity) {
                FindingSeverities::CRITICAL, FindingSeverities::HIGH => 92,
                FindingSeverities::MEDIUM => 86,
                FindingSeverities::LOW => 78,
                default => 70,
            },
            default => 75,
        };

        if ($cvss !== null && $cvss >= 9) {
            return min(100, $base + 4);
        }

        return $base;
    }

    private function severity(string $severity): string
    {
        $severity = strtolower(trim($severity));

        return in_array($severity, FindingSeverities::all(), true) ? $severity : FindingSeverities::INFO;
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

    private function nullableString(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim((string) $value);

        return $value === '' ? null : $value;
    }

    private function nullableFloat(mixed $value): ?float
    {
        if ($value === null || $value === '') {
            return null;
        }

        return is_numeric($value) ? (float) $value : null;
    }

    private function parseDate(mixed $value): ?Carbon
    {
        if (! is_string($value) || trim($value) === '') {
            return null;
        }

        try {
            return Carbon::parse($value);
        } catch (\Throwable) {
            return null;
        }
    }

    private function normalizeText(string $value): string
    {
        return (string) Str::of($value)->lower()->replaceMatches('/[^a-z0-9]+/', ' ')->squish();
    }

    private function pathFromUrl(string $url): string
    {
        $path = parse_url($url, PHP_URL_PATH);

        return is_string($path) && $path !== '' ? $path : '/';
    }

    private function redact(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }

        $redacted = [];

        foreach ($value as $key => $item) {
            $keyString = strtolower((string) $key);

            if (preg_match('/password|secret|token|cookie|authorization|api[_-]?key/', $keyString) === 1) {
                $redacted[$key] = '[redacted]';
                continue;
            }

            $redacted[$key] = $this->redact($item);
        }

        return $redacted;
    }
}
