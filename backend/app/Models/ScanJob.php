<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ScanJob extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_id',
        'workspace_id',
        'website_id',
        'scan_plan_item_id',
        'job_type',
        'scanner_key',
        'scan_module',
        'template_group',
        'status',
        'priority',
        'recommendation_score',
        'safe_default',
        'progress',
        'attempts',
        'attempt_count',
        'max_attempts',
        'timeout_seconds',
        'started_at',
        'finished_at',
        'completed_at',
        'duration_ms',
        'progress_percent',
        'request_count',
        'result_summary',
        'worker_id',
        'lock_key',
        'queue_name',
        'max_requests',
        'max_runtime',
        'max_memory',
        'cancellation_token',
        'cancel_requested_at',
        'last_heartbeat_at',
        'logs',
        'error_message',
    ];

    protected function casts(): array
    {
        return [
            'progress' => 'integer',
            'attempts' => 'integer',
            'priority' => 'integer',
            'recommendation_score' => 'integer',
            'safe_default' => 'boolean',
            'attempt_count' => 'integer',
            'max_attempts' => 'integer',
            'timeout_seconds' => 'integer',
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
            'completed_at' => 'datetime',
            'duration_ms' => 'integer',
            'progress_percent' => 'integer',
            'request_count' => 'integer',
            'result_summary' => 'array',
            'max_requests' => 'integer',
            'max_runtime' => 'integer',
            'max_memory' => 'integer',
            'cancel_requested_at' => 'datetime',
            'last_heartbeat_at' => 'datetime',
            'logs' => 'array',
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
     * @return BelongsTo<Workspace, $this>
     */
    public function workspace(): BelongsTo
    {
        return $this->belongsTo(Workspace::class);
    }

    /**
     * @return BelongsTo<Website, $this>
     */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }

    /**
     * @return BelongsTo<ScanPlanItem, $this>
     */
    public function scanPlanItem(): BelongsTo
    {
        return $this->belongsTo(ScanPlanItem::class);
    }

    /**
     * @return HasMany<RawArtifact, $this>
     */
    public function rawArtifacts(): HasMany
    {
        return $this->hasMany(RawArtifact::class);
    }

    /**
     * @return HasMany<ScanJobTimeline, $this>
     */
    public function timelines(): HasMany
    {
        return $this->hasMany(ScanJobTimeline::class);
    }

    /**
     * @return HasMany<ScanJobLog, $this>
     */
    public function jobLogs(): HasMany
    {
        return $this->hasMany(ScanJobLog::class);
    }
}
