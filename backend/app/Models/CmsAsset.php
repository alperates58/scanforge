<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CmsAsset extends Model
{
    use HasFactory;

    protected $fillable = [
        'website_id',
        'cms_name',
        'asset_type',
        'asset_name',
        'detected_version',
        'source',
        'confidence',
        'analysis_required',
        'first_seen_at',
        'last_seen_at',
    ];

    protected $casts = [
        'analysis_required' => 'boolean',
        'first_seen_at' => 'datetime',
        'last_seen_at' => 'datetime',
    ];

    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }
}
