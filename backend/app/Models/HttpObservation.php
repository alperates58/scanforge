<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class HttpObservation extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'asset_discovery_id',
        'url',
        'final_url',
        'status_code',
        'title',
        'server_header',
        'powered_by_header',
        'headers',
        'response_headers_raw',
        'cookies',
        'redirect_chain',
        'response_time_ms',
        'body_sha256',
        'body_hash_sha256',
        'favicon_hash',
        'html_lang',
        'html_doctype',
        'html_size_bytes',
        'body_title',
        'body_description',
        'generator_meta',
        'observed_at',
    ];

    protected function casts(): array
    {
        return [
            'status_code' => 'integer',
            'headers' => 'array',
            'response_headers_raw' => 'array',
            'cookies' => 'array',
            'redirect_chain' => 'array',
            'response_time_ms' => 'integer',
            'html_size_bytes' => 'integer',
            'observed_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<AssetDiscovery, $this> */
    public function assetDiscovery(): BelongsTo
    {
        return $this->belongsTo(AssetDiscovery::class);
    }

    /** @return HasMany<SecurityHeaderObservation, $this> */
    public function securityHeaders(): HasMany
    {
        return $this->hasMany(SecurityHeaderObservation::class);
    }

    /** @return HasMany<CookieObservation, $this> */
    public function cookieObservations(): HasMany
    {
        return $this->hasMany(CookieObservation::class);
    }

    /** @return HasMany<RedirectObservation, $this> */
    public function redirects(): HasMany
    {
        return $this->hasMany(RedirectObservation::class);
    }
}
