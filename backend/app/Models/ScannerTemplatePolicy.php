<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScannerTemplatePolicy extends Model
{
    use HasFactory;

    protected $fillable = [
        'scanner_key',
        'template_group',
        'allowed',
        'safety_level',
        'blocked_tags',
        'allowed_tags',
        'reason',
    ];

    protected function casts(): array
    {
        return [
            'allowed' => 'boolean',
            'blocked_tags' => 'array',
            'allowed_tags' => 'array',
        ];
    }
}
