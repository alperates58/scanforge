<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class TechnologyConflict extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'left_fingerprint_id',
        'right_fingerprint_id',
        'category',
        'severity',
        'reason',
        'status',
        'detected_at',
    ];

    protected function casts(): array
    {
        return [
            'detected_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<TechnologyFingerprint, $this> */
    public function leftFingerprint(): BelongsTo
    {
        return $this->belongsTo(TechnologyFingerprint::class, 'left_fingerprint_id');
    }

    /** @return BelongsTo<TechnologyFingerprint, $this> */
    public function rightFingerprint(): BelongsTo
    {
        return $this->belongsTo(TechnologyFingerprint::class, 'right_fingerprint_id');
    }
}
