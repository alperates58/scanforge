<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TemplateManifest extends Model
{
    use HasFactory;

    protected $fillable = [
        'scanner_key',
        'template_id',
        'group',
        'severity',
        'tags',
        'author',
        'signed',
        'last_updated',
        'deprecated',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'tags' => 'array',
            'signed' => 'boolean',
            'last_updated' => 'datetime',
            'deprecated' => 'boolean',
            'metadata' => 'array',
        ];
    }
}
