<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SecurityHeaderObservation extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'asset_discovery_id',
        'http_observation_id',
        'header_key',
        'present',
        'value',
        'recommendation',
        'observed_at',
    ];

    protected function casts(): array
    {
        return [
            'present' => 'boolean',
            'observed_at' => 'datetime',
        ];
    }
}
