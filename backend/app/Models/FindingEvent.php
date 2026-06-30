<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class FindingEvent extends Model
{
    use HasFactory;

    protected $fillable = [
        'finding_id',
        'workspace_id',
        'website_id',
        'scan_id',
        'old_status',
        'new_status',
        'reason',
        'changed_by_user_id',
        'metadata',
        'changed_at',
    ];

    protected function casts(): array
    {
        return [
            'metadata' => 'array',
            'changed_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<Finding, $this> */
    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }
}
