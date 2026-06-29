<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanJobLog extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_job_id',
        'scan_id',
        'workspace_id',
        'timestamp',
        'level',
        'message',
        'context',
    ];

    protected function casts(): array
    {
        return [
            'timestamp' => 'datetime',
            'context' => 'array',
        ];
    }

    /** @return BelongsTo<ScanJob, $this> */
    public function scanJob(): BelongsTo
    {
        return $this->belongsTo(ScanJob::class);
    }

    /** @return BelongsTo<Scan, $this> */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
