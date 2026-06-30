<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Finding extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_id',
        'workspace_id',
        'website_id',
        'asset_discovery_id',
        'raw_artifact_id',
        'canonical_finding_id',
        'finding_taxonomy_id',
        'asset_type',
        'asset_id',
        'asset_identifier',
        'title',
        'normalized_title',
        'severity',
        'confidence',
        'confidence_score',
        'false_positive_risk',
        'risk_score',
        'priority',
        'affected_url',
        'affected_component',
        'affected_parameter',
        'parameter',
        'source_tool',
        'scanner_key',
        'template_id',
        'cwe',
        'cwe_json',
        'cve',
        'cve_json',
        'cvss',
        'cvss_score',
        'owasp_category',
        'evidence',
        'evidence_json',
        'remediation',
        'fingerprint_hash',
        'dedupe_hash',
        'correlation_key',
        'correlation_score',
        'related_finding_id',
        'first_seen_at',
        'last_seen_at',
        'resolved_at',
        'reopened_at',
        'occurrence_count',
        'matched_at',
        'description',
        'normalized_description',
        'references',
        'ai_summary',
        'status',
        'false_positive_notes',
        'analysis_required',
        'analysis_version',
        'analysis_status',
        'sla_due_at',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'confidence' => 'float',
            'confidence_score' => 'integer',
            'risk_score' => 'integer',
            'correlation_score' => 'integer',
            'cvss' => 'float',
            'cvss_score' => 'float',
            'cwe_json' => 'array',
            'cve_json' => 'array',
            'evidence_json' => 'array',
            'references' => 'array',
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'resolved_at' => 'datetime',
            'reopened_at' => 'datetime',
            'matched_at' => 'datetime',
            'occurrence_count' => 'integer',
            'false_positive_notes' => 'array',
            'analysis_required' => 'boolean',
            'sla_due_at' => 'datetime',
            'metadata' => 'array',
        ];
    }

    /**
     * @return BelongsTo<Scan, $this>
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    /**
     * @return BelongsTo<Website, $this>
     */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }

    /**
     * @return BelongsTo<Workspace, $this>
     */
    public function workspace(): BelongsTo
    {
        return $this->belongsTo(Workspace::class);
    }

    /**
     * @return BelongsTo<CanonicalFinding, $this>
     */
    public function canonicalFinding(): BelongsTo
    {
        return $this->belongsTo(CanonicalFinding::class);
    }

    /**
     * @return BelongsTo<FindingTaxonomy, $this>
     */
    public function taxonomy(): BelongsTo
    {
        return $this->belongsTo(FindingTaxonomy::class, 'finding_taxonomy_id');
    }

    /**
     * @return BelongsTo<Finding, $this>
     */
    public function relatedFinding(): BelongsTo
    {
        return $this->belongsTo(Finding::class, 'related_finding_id');
    }

    /**
     * @return BelongsTo<AssetDiscovery, $this>
     */
    public function assetDiscovery(): BelongsTo
    {
        return $this->belongsTo(AssetDiscovery::class);
    }

    /**
     * @return BelongsTo<RawArtifact, $this>
     */
    public function rawArtifact(): BelongsTo
    {
        return $this->belongsTo(RawArtifact::class);
    }

    /**
     * @return HasMany<FindingHistory, $this>
     */
    public function histories(): HasMany
    {
        return $this->hasMany(FindingHistory::class);
    }

    /**
     * @return HasMany<FindingSource, $this>
     */
    public function sources(): HasMany
    {
        return $this->hasMany(FindingSource::class);
    }

    /**
     * @return HasMany<FindingEvent, $this>
     */
    public function events(): HasMany
    {
        return $this->hasMany(FindingEvent::class);
    }

    /**
     * @return HasMany<FindingEvidence, $this>
     */
    public function evidences(): HasMany
    {
        return $this->hasMany(FindingEvidence::class);
    }

    /**
     * @return HasMany<RiskScoreHistory, $this>
     */
    public function riskScoreHistories(): HasMany
    {
        return $this->hasMany(RiskScoreHistory::class);
    }

    /**
     * @return HasMany<ConfidenceHistory, $this>
     */
    public function confidenceHistories(): HasMany
    {
        return $this->hasMany(ConfidenceHistory::class);
    }
}
