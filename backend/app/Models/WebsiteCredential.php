<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class WebsiteCredential extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'name',
        'type',
        'encrypted_payload',
        'created_by_user_id',
        'last_used_at',
        'expires_at',
    ];

    protected $hidden = [
        'encrypted_payload',
    ];

    protected function casts(): array
    {
        return [
            'encrypted_payload' => 'encrypted:array',
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
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
