<?php

namespace App\Fingerprinting\Contracts;

interface FingerprintPluginInterface
{
    public function key(): string;

    public function label(): string;

    /**
     * @return list<\App\Fingerprinting\Support\RuleGroup>
     */
    public function ruleGroups(): array;
}
