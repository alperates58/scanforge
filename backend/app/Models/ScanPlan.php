<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ScanPlan extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'asset_discovery_id',
        'status',
        'coverage_prediction',
        'estimated_runtime_seconds',
        'estimated_requests',
        'estimated_cpu',
        'estimated_memory_mb',
        'safe_mode',
        'analysis_required',
        'generated_from',
        'summary',
        'generated_at',
    ];

    protected function casts(): array
    {
        return [
            'coverage_prediction' => 'integer',
            'estimated_runtime_seconds' => 'integer',
            'estimated_requests' => 'integer',
            'estimated_cpu' => 'float',
            'estimated_memory_mb' => 'integer',
            'safe_mode' => 'boolean',
            'analysis_required' => 'boolean',
            'summary' => 'array',
            'generated_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<Website, $this> */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }

    /** @return BelongsTo<AssetDiscovery, $this> */
    public function assetDiscovery(): BelongsTo
    {
        return $this->belongsTo(AssetDiscovery::class);
    }

    /** @return HasMany<ScanPlanItem, $this> */
    public function items(): HasMany
    {
        return $this->hasMany(ScanPlanItem::class);
    }
}
