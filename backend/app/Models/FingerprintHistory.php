<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class FingerprintHistory extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'fingerprint_id',
        'technology_key',
        'old_version',
        'new_version',
        'confidence_old',
        'confidence_new',
        'metadata',
        'detected_at',
    ];

    protected function casts(): array
    {
        return [
            'confidence_old' => 'integer',
            'confidence_new' => 'integer',
            'metadata' => 'array',
            'detected_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<TechnologyFingerprint, $this> */
    public function fingerprint(): BelongsTo
    {
        return $this->belongsTo(TechnologyFingerprint::class, 'fingerprint_id');
    }
}
