<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class TechnologyRelationship extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'parent_fingerprint_id',
        'child_fingerprint_id',
        'parent_technology_key',
        'child_technology_key',
        'relationship_type',
        'confidence',
        'metadata',
        'detected_at',
    ];

    protected function casts(): array
    {
        return [
            'confidence' => 'integer',
            'metadata' => 'array',
            'detected_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<TechnologyFingerprint, $this> */
    public function parentFingerprint(): BelongsTo
    {
        return $this->belongsTo(TechnologyFingerprint::class, 'parent_fingerprint_id');
    }

    /** @return BelongsTo<TechnologyFingerprint, $this> */
    public function childFingerprint(): BelongsTo
    {
        return $this->belongsTo(TechnologyFingerprint::class, 'child_fingerprint_id');
    }
}
