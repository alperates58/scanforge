<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ArtifactManifest extends Model
{
    use HasFactory;

    protected $fillable = [
        'raw_artifact_id',
        'checksum',
        'size',
        'mime',
        'compressed',
        'retention_policy',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'size' => 'integer',
            'compressed' => 'boolean',
            'metadata' => 'array',
        ];
    }

    /** @return BelongsTo<RawArtifact, $this> */
    public function rawArtifact(): BelongsTo
    {
        return $this->belongsTo(RawArtifact::class);
    }
}
