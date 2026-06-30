<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SuppressionRule extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'scanner_key',
        'template_id',
        'host',
        'action',
        'expires_at',
        'reason',
        'created_by_user_id',
        'enabled',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'enabled' => 'boolean',
            'metadata' => 'array',
        ];
    }

    /** @return BelongsTo<Website, $this> */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }
}
