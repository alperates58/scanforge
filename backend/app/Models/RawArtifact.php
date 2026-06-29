<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class RawArtifact extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_id',
        'scan_job_id',
        'tool_name',
        'scanner_key',
        'artifact_type',
        'file_path',
        'json_payload',
        'content',
        'sha256',
    ];

    protected function casts(): array
    {
        return [
            'json_payload' => 'array',
            'content' => 'array',
        ];
    }

    /**
     * @return BelongsTo<Scan, $this>
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    /**
     * @return BelongsTo<ScanJob, $this>
     */
    public function scanJob(): BelongsTo
    {
        return $this->belongsTo(ScanJob::class);
    }
}
