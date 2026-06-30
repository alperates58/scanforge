<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class FindingTaxonomy extends Model
{
    use HasFactory;

    protected $fillable = [
        'category',
        'subcategory',
        'owasp_category',
        'asvs_control',
        'cwe',
        'capec',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'metadata' => 'array',
        ];
    }

    /** @return HasMany<CanonicalFinding, $this> */
    public function canonicalFindings(): HasMany
    {
        return $this->hasMany(CanonicalFinding::class);
    }

    /** @return HasMany<Finding, $this> */
    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class);
    }
}
