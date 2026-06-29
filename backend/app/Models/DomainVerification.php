<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DomainVerification extends Model
{
    use HasFactory;

    protected $fillable = [
        'website_id',
        'method',
        'verification_token_hash',
        'status',
        'checked_at',
        'verified_at',
        'expires_at',
        'last_error',
        'evidence',
    ];

    protected function casts(): array
    {
        return [
            'checked_at' => 'datetime',
            'verified_at' => 'datetime',
            'expires_at' => 'datetime',
            'evidence' => 'array',
        ];
    }

    /**
     * @return BelongsTo<Website, $this>
     */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }
}
