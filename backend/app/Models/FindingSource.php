<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class FindingSource extends Model
{
    use HasFactory;

    protected $fillable = [
        'finding_id',
        'workspace_id',
        'website_id',
        'scanner_key',
        'scan_job_id',
        'raw_artifact_id',
        'template_id',
        'source_severity',
        'source_confidence',
        'source_payload',
        'observed_at',
    ];

    protected function casts(): array
    {
        return [
            'source_confidence' => 'integer',
            'source_payload' => 'array',
            'observed_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<Finding, $this> */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }

    /** @return BelongsTo<Website, $this> */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }
}
