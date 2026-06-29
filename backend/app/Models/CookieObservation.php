<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class CookieObservation extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'asset_discovery_id',
        'http_observation_id',
        'name',
        'domain',
        'path',
        'secure',
        'http_only',
        'same_site',
        'expires_at',
        'persistent',
        'host_only',
        'observed_at',
    ];

    protected function casts(): array
    {
        return [
            'secure' => 'boolean',
            'http_only' => 'boolean',
            'expires_at' => 'datetime',
            'persistent' => 'boolean',
            'host_only' => 'boolean',
            'observed_at' => 'datetime',
        ];
    }
}
