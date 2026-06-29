<?php

namespace App\Http\Requests\Api;

use App\Support\WebsiteEnums;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreWebsiteRequest extends FormRequest
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
            'url' => ['required', 'string', 'max:2048'],
            'environment' => ['nullable', 'string', Rule::in(WebsiteEnums::environments())],
            'importance' => ['nullable', 'string', Rule::in(WebsiteEnums::importanceLevels())],
            'notes' => ['nullable', 'string', 'max:5000'],
            'tags' => ['nullable', 'array', 'max:20'],
            'tags.*' => ['string', 'max:40', 'regex:/^[a-z0-9][a-z0-9_-]*$/i'],
        ];
    }
}
