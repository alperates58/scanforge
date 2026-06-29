<?php

namespace App\Fingerprinting\Support;

class RuleGroup
{
    /**
     * @param list<FingerprintRule> $rules
     * @param list<string> $parents
     * @param list<string> $conflictsWith
     */
    public function __construct(
        public readonly string $technologyKey,
        public readonly string $technologyName,
        public readonly string $category,
        public readonly array $rules,
        public readonly array $parents = [],
        public readonly array $conflictsWith = [],
        public readonly ?string $coverageCategory = null,
        public readonly ?string $cpeVendor = null,
        public readonly ?string $cpeProduct = null,
        public readonly ?string $conflictGroup = null,
    ) {
    }
}
