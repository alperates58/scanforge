<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScannerVersion extends Model
{
    use HasFactory;

    protected $fillable = [
        'scanner_key',
        'binary_version',
        'templates_version',
        'last_checked_at',
        'status',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'last_checked_at' => 'datetime',
            'metadata' => 'array',
        ];
    }
}
