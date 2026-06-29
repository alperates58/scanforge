<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class TechnologyFingerprint extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'scan_id',
        'asset_discovery_id',
        'technology_key',
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
        'first_detected_at',
        'last_detected_at',
        'fingerprint_hash',
    ];

    protected function casts(): array
    {
        return [
            'confidence' => 'float',
            'confidence_score' => 'integer',
            'quality_score' => 'integer',
            'cpe_candidates' => 'array',
            'evidence' => 'array',
            'metadata' => 'array',
            'scanner_recommendations' => 'array',
            'analysis_required' => 'boolean',
            'is_active' => 'boolean',
            'first_detected_at' => 'datetime',
            'last_detected_at' => 'datetime',
        ];
    }

    /**
     * @return BelongsTo<Workspace, $this>
     */
    public function workspace(): BelongsTo
    {
        return $this->belongsTo(Workspace::class);
    }

    /**
     * @return BelongsTo<Website, $this>
     */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }

    /**
     * @return BelongsTo<Scan, $this>
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    /**
     * @return BelongsTo<AssetDiscovery, $this>
     */
    public function assetDiscovery(): BelongsTo
    {
        return $this->belongsTo(AssetDiscovery::class);
    }

    /**
     * @return HasMany<TechnologyEvidence, $this>
     */
    public function evidences(): HasMany
    {
        return $this->hasMany(TechnologyEvidence::class, 'fingerprint_id');
    }

    /**
     * @return HasMany<FingerprintHistory, $this>
     */
    public function histories(): HasMany
    {
        return $this->hasMany(FingerprintHistory::class, 'fingerprint_id');
    }
}
