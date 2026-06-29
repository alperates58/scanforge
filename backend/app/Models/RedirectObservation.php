<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class RedirectObservation extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'asset_discovery_id',
        'http_observation_id',
        'order',
        'from_url',
        'to_url',
        'status_code',
        'observed_at',
    ];

    protected function casts(): array
    {
        return [
            'order' => 'integer',
            'status_code' => 'integer',
            'observed_at' => 'datetime',
        ];
    }
}
