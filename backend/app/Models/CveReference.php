<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class CveReference extends Model
{
    use HasFactory;

    protected $fillable = [
        'cve',
        'cvss',
        'epss',
        'kev',
        'vendor',
        'product',
        'version',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'cvss' => 'float',
            'epss' => 'float',
            'kev' => 'boolean',
            'metadata' => 'array',
        ];
    }
}
