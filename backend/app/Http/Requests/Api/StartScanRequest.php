<?php

namespace App\Http\Requests\Api;

use App\Support\ScanTypes;
use App\Support\SafetyModes;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StartScanRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'scan_type' => ['required', 'string', Rule::in(ScanTypes::all())],
            'consent_accepted' => ['accepted'],
            'scan_plan_id' => ['nullable', 'integer'],
            'safety_mode' => ['nullable', 'string', Rule::in(SafetyModes::all())],
            'credential_id' => ['nullable', 'integer'],
            'options' => ['nullable', 'array'],
        ];
    }
}
