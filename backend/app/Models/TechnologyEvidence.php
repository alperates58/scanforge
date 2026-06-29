<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use RuntimeException;

class TechnologyEvidence extends Model
{
    use HasFactory;

    protected $table = 'technology_evidences';

    protected $fillable = [
        'workspace_id',
        'website_id',
        'fingerprint_id',
        'asset_discovery_id',
        'source_type',
        'source_key',
        'source_value',
        'confidence',
        'raw_data',
        'detected_at',
    ];

    protected function casts(): array
    {
        return [
            'confidence' => 'integer',
            'raw_data' => 'array',
            'detected_at' => 'datetime',
        ];
    }

    protected static function booted(): void
    {
        static::updating(function (): void {
            throw new RuntimeException('Technology evidence is immutable; create a new evidence row instead.');
        });

        static::deleting(function (): void {
            throw new RuntimeException('Technology evidence is immutable and cannot be deleted through the model.');
        });
    }

    /** @return BelongsTo<TechnologyFingerprint, $this> */
    public function fingerprint(): BelongsTo
    {
        return $this->belongsTo(TechnologyFingerprint::class, 'fingerprint_id');
    }

    /** @return BelongsTo<Website, $this> */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }
}
