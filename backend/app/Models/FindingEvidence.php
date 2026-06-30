<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class FindingEvidence extends Model
{
    use HasFactory;

    protected $table = 'finding_evidences';

    protected $fillable = [
        'finding_id',
        'workspace_id',
        'website_id',
        'type',
        'mime',
        'sha256',
        'artifact_id',
        'thumbnail',
        'preview',
        'metadata',
        'observed_at',
    ];

    protected function casts(): array
    {
        return [
            'metadata' => 'array',
            'observed_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<Finding, $this> */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }

    /** @return BelongsTo<RawArtifact, $this> */
    public function artifact(): BelongsTo
    {
        return $this->belongsTo(RawArtifact::class, 'artifact_id');
    }
}
