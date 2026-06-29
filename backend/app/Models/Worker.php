<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Worker extends Model
{
    use HasFactory;

    protected $table = 'scan_workers';

    protected $fillable = [
        'worker_id',
        'hostname',
        'version',
        'supported_scanners',
        'status',
        'current_jobs',
        'max_jobs',
        'last_heartbeat',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'supported_scanners' => 'array',
            'current_jobs' => 'integer',
            'max_jobs' => 'integer',
            'last_heartbeat' => 'datetime',
            'metadata' => 'array',
        ];
    }
}
