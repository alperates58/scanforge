<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class FindingDelta extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'scan_id',
        'previous_scan_id',
        'finding_id',
        'delta_type',
        'old_status',
        'new_status',
        'old_score',
        'new_score',
        'old_severity',
        'new_severity',
        'reason',
        'metadata',
        'calculated_at',
    ];

    protected function casts(): array
    {
        return [
            'old_score' => 'integer',
            'new_score' => 'integer',
            'metadata' => 'array',
            'calculated_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<Finding, $this> */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }
}
