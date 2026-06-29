<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

class Scan extends Model
{
    use HasFactory;

    protected $fillable = [
        'website_id',
        'workspace_id',
        'scan_plan_id',
        'scan_type',
        'status',
        'score',
        'safe_mode',
        'safety_mode',
        'consent_accepted_at',
        'requested_by_user_id',
        'request_options',
        'request_budget',
        'timeout_seconds',
        'started_at',
        'finished_at',
        'completed_at',
        'cancelled_at',
        'duration_ms',
        'progress_percent',
        'total_jobs',
        'completed_jobs',
        'failed_jobs',
        'skipped_jobs',
        'metadata',
        'discovery_completed_at',
        'fingerprint_completed_at',
        'passive_scan_completed_at',
        'deep_scan_completed_at',
        'ai_analysis_completed_at',
        'error_message',
    ];

    protected function casts(): array
    {
        return [
            'safe_mode' => 'boolean',
            'consent_accepted_at' => 'datetime',
            'request_options' => 'array',
            'request_budget' => 'integer',
            'timeout_seconds' => 'integer',
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
            'completed_at' => 'datetime',
            'cancelled_at' => 'datetime',
            'duration_ms' => 'integer',
            'progress_percent' => 'integer',
            'total_jobs' => 'integer',
            'completed_jobs' => 'integer',
            'failed_jobs' => 'integer',
            'skipped_jobs' => 'integer',
            'metadata' => 'array',
            'discovery_completed_at' => 'datetime',
            'fingerprint_completed_at' => 'datetime',
            'passive_scan_completed_at' => 'datetime',
            'deep_scan_completed_at' => 'datetime',
            'ai_analysis_completed_at' => 'datetime',
        ];
    }

    /**
     * @return BelongsTo<Website, $this>
     */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }

    /**
     * @return BelongsTo<Workspace, $this>
     */
    public function workspace(): BelongsTo
    {
        return $this->belongsTo(Workspace::class);
    }

    /**
     * @return BelongsTo<ScanPlan, $this>
     */
    public function scanPlan(): BelongsTo
    {
        return $this->belongsTo(ScanPlan::class);
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function requestedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'requested_by_user_id');
    }

    /**
     * @return HasMany<ScanJob, $this>
     */
    public function jobs(): HasMany
    {
        return $this->hasMany(ScanJob::class);
    }

    /**
     * @return HasMany<Finding, $this>
     */
    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class);
    }

    /**
     * @return HasOne<AiAnalysis, $this>
     */
    public function aiAnalysis(): HasOne
    {
        return $this->hasOne(AiAnalysis::class);
    }
}
