<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScannerMetric extends Model
{
    use HasFactory;

    protected $fillable = [
        'scanner_key',
        'runs',
        'success',
        'failed',
        'timeout',
        'avg_runtime',
        'avg_findings',
        'last_run_at',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'runs' => 'integer',
            'success' => 'integer',
            'failed' => 'integer',
            'timeout' => 'integer',
            'avg_runtime' => 'float',
            'avg_findings' => 'float',
            'last_run_at' => 'datetime',
            'metadata' => 'array',
        ];
    }
}
