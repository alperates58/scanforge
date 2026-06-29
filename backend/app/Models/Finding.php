<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Finding extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_id',
        'website_id',
        'asset_discovery_id',
        'raw_artifact_id',
        'title',
        'severity',
        'confidence',
        'affected_url',
        'source_tool',
        'cwe',
        'cve',
        'cvss',
        'owasp_category',
        'evidence',
        'remediation',
        'fingerprint_hash',
        'status',
        'false_positive_notes',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'confidence' => 'float',
            'cvss' => 'float',
            'false_positive_notes' => 'array',
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
     * @return BelongsTo<AssetDiscovery, $this>
     */
    public function assetDiscovery(): BelongsTo
    {
        return $this->belongsTo(AssetDiscovery::class);
    }
}
