<?php

namespace App\Fingerprinting\Support;

use Closure;

class FingerprintRule
{
    public function __construct(
        public readonly string $key,
        public readonly string $sourceType,
        public readonly ?string $sourceKey,
        public readonly int $confidence,
        public readonly string $description,
        private readonly Closure $matcher,
    ) {
    }

    /**
     * @return array<string, mixed>|null
     */
    public function evaluate(FingerprintContext $context): ?array
    {
        $match = ($this->matcher)($context);

        if ($match === false || $match === null || $match === '') {
            return null;
        }

        if ($match === true) {
            $match = [];
        }

        if (is_string($match)) {
            $match = ['source_value' => $match];
        }

        if (! is_array($match)) {
            return null;
        }

        return [
            'rule_key' => $this->key,
            'source_type' => $match['source_type'] ?? $this->sourceType,
            'source_key' => $match['source_key'] ?? $this->sourceKey,
            'source_value' => $match['source_value'] ?? $match['value'] ?? $this->description,
            'confidence' => (int) ($match['confidence'] ?? $this->confidence),
            'version' => $match['version'] ?? null,
            'raw_data' => [
                'description' => $this->description,
                'rule_key' => $this->key,
                ...($match['raw_data'] ?? []),
            ],
        ];
    }
}
