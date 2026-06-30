<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class CanonicalFinding extends Model
{
    use HasFactory;

    protected $fillable = [
        'finding_taxonomy_id',
        'normalized_key',
        'default_title',
        'default_description',
        'default_remediation',
        'default_references',
        'ai_summary_template',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'default_references' => 'array',
            'metadata' => 'array',
        ];
    }

    /** @return BelongsTo<FindingTaxonomy, $this> */
    public function taxonomy(): BelongsTo
    {
        return $this->belongsTo(FindingTaxonomy::class, 'finding_taxonomy_id');
    }

    /** @return HasMany<Finding, $this> */
    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class);
    }
}
