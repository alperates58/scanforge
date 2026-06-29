<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanPlanItem extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_plan_id',
        'technology_fingerprint_id',
        'technology_key',
        'scanner_key',
        'template_group',
        'scan_module',
        'priority',
        'recommendation_score',
        'estimated_duration_seconds',
        'estimated_requests',
        'estimated_cpu',
        'estimated_memory_mb',
        'safe_mode',
        'reason',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'priority' => 'integer',
            'recommendation_score' => 'integer',
            'estimated_duration_seconds' => 'integer',
            'estimated_requests' => 'integer',
            'estimated_cpu' => 'float',
            'estimated_memory_mb' => 'integer',
            'safe_mode' => 'boolean',
            'metadata' => 'array',
        ];
    }

    /** @return BelongsTo<ScanPlan, $this> */
    public function scanPlan(): BelongsTo
    {
        return $this->belongsTo(ScanPlan::class);
    }

    /** @return BelongsTo<TechnologyFingerprint, $this> */
    public function technologyFingerprint(): BelongsTo
    {
        return $this->belongsTo(TechnologyFingerprint::class);
    }
}
