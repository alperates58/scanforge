<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScannerCapability extends Model
{
    use HasFactory;

    protected $fillable = [
        'technology_key',
        'scanner_key',
        'template_group',
        'scan_module',
        'min_confidence',
        'min_version',
        'max_version',
        'supported_versions',
        'enabled',
        'safe_default',
        'priority',
        'estimated_duration_seconds',
        'estimated_requests',
        'estimated_cpu',
        'estimated_memory_mb',
        'safe_mode',
        'description',
    ];

    protected function casts(): array
    {
        return [
            'min_confidence' => 'integer',
            'supported_versions' => 'array',
            'enabled' => 'boolean',
            'safe_default' => 'boolean',
            'priority' => 'integer',
            'estimated_duration_seconds' => 'integer',
            'estimated_requests' => 'integer',
            'estimated_cpu' => 'float',
            'estimated_memory_mb' => 'integer',
            'safe_mode' => 'boolean',
        ];
    }
}
