<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class RiskScoreHistory extends Model
{
    use HasFactory;

    protected $fillable = [
        'finding_id',
        'workspace_id',
        'website_id',
        'old_score',
        'new_score',
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
