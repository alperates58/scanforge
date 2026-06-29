<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AiAnalysis extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_id',
        'model',
        'prompt_version',
        'model_provider',
        'model_name',
        'risk_level',
        'executive_summary',
        'business_impact',
        'priority_fixes',
        'false_positive_notes',
        'technology_specific_recommendations',
        'next_scan_recommendation',
        'input_tokens',
        'output_tokens',
        'cost_usd',
        'duration_ms',
        'raw_json',
    ];

    protected function casts(): array
    {
        return [
            'priority_fixes' => 'array',
            'false_positive_notes' => 'array',
            'technology_specific_recommendations' => 'array',
            'input_tokens' => 'integer',
            'output_tokens' => 'integer',
            'cost_usd' => 'float',
            'duration_ms' => 'integer',
            'raw_json' => 'array',
        ];
    }

    /**
     * @return BelongsTo<Scan, $this>
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
