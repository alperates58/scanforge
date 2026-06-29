<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SslCertificate extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'asset_discovery_id',
        'host',
        'issuer',
        'subject',
        'valid_from',
        'valid_to',
        'days_remaining',
        'san',
        'fingerprint_sha256',
        'tls_summary',
        'observed_at',
    ];

    protected function casts(): array
    {
        return [
            'valid_from' => 'datetime',
            'valid_to' => 'datetime',
            'days_remaining' => 'integer',
            'san' => 'array',
            'tls_summary' => 'array',
            'observed_at' => 'datetime',
        ];
    }
}
