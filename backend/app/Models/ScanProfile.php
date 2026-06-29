<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanProfile extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'name',
        'scan_type',
        'enabled_modules',
        'rate_limit',
        'timeout_seconds',
        'is_default',
        'authenticated',
        'created_by_user_id',
    ];

    protected function casts(): array
    {
        return [
            'enabled_modules' => 'array',
            'rate_limit' => 'array',
            'timeout_seconds' => 'integer',
            'is_default' => 'boolean',
            'authenticated' => 'boolean',
        ];
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
     * @return BelongsTo<User, $this>
     */
    public function createdBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by_user_id');
    }
}
