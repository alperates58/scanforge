<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanSchedule extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'scan_plan_id',
        'scan_type',
        'safety_mode',
        'cron',
        'timezone',
        'enabled',
        'last_run',
        'next_run',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'last_run' => 'datetime',
            'next_run' => 'datetime',
            'metadata' => 'array',
        ];
    }

    /** @return BelongsTo<Workspace, $this> */
    public function workspace(): BelongsTo
    {
        return $this->belongsTo(Workspace::class);
    }

    /** @return BelongsTo<Website, $this> */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }

    /** @return BelongsTo<ScanPlan, $this> */
    public function scanPlan(): BelongsTo
    {
        return $this->belongsTo(ScanPlan::class);
    }
}
