<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class DomainWhoisSnapshot extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'asset_discovery_id',
        'registrar',
        'created_at_remote',
        'expires_at_remote',
        'updated_at_remote',
        'age_days',
        'raw_summary',
        'observed_at',
    ];

    protected function casts(): array
    {
        return [
            'created_at_remote' => 'datetime',
            'expires_at_remote' => 'datetime',
            'updated_at_remote' => 'datetime',
            'age_days' => 'integer',
            'raw_summary' => 'array',
            'observed_at' => 'datetime',
        ];
    }
}
