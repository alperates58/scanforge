<?php

namespace App\Services;

use App\Models\ScannerTemplatePolicy;

class ScannerTemplatePolicyService
{
    /**
     * @return array{allowed: bool, safety_level: string, allowed_tags: list<string>, blocked_tags: list<string>, reason: string|null}
     */
    public function evaluate(string $scannerKey, ?string $templateGroup): array
    {
        $templateGroup = trim((string) $templateGroup);

        if ($templateGroup === '') {
            return $this->deny('missing_template_group');
        }

        $policy = ScannerTemplatePolicy::query()
            ->where('scanner_key', $scannerKey)
            ->where('template_group', $templateGroup)
            ->first();

        if (! $policy) {
            $policy = $this->policyFromConfig($scannerKey, $templateGroup);
        }

        if (! $policy) {
            return $this->deny('template_group_not_allowlisted');
        }

        $blockedTags = array_values(array_unique(array_merge(
            (array) config('nuclei.blocked_template_tags', []),
            (array) ($policy->blocked_tags ?? []),
        )));
        $allowedTags = array_values(array_unique((array) ($policy->allowed_tags ?? config('nuclei.safe_template_tags', []))));

        if ($policy->safety_level === 'deep' && ! (bool) config('scanforge.scanner.enable_deep_scan', false)) {
            return [
                'allowed' => false,
                'safety_level' => 'blocked',
                'allowed_tags' => [],
                'blocked_tags' => $blockedTags,
                'reason' => 'deep_scan_disabled',
            ];
        }

        return [
            'allowed' => (bool) $policy->allowed,
            'safety_level' => (string) $policy->safety_level,
            'allowed_tags' => $allowedTags,
            'blocked_tags' => $blockedTags,
            'reason' => $policy->reason,
        ];
    }

    private function policyFromConfig(string $scannerKey, string $templateGroup): ?ScannerTemplatePolicy
    {
        if ($scannerKey !== 'nuclei') {
            return null;
        }

        foreach ((array) config('nuclei.policies', []) as $policy) {
            if (($policy['template_group'] ?? null) !== $templateGroup) {
                continue;
            }

            return new ScannerTemplatePolicy([
                'scanner_key' => 'nuclei',
                'template_group' => $templateGroup,
                'allowed' => (bool) ($policy['allowed'] ?? false),
                'safety_level' => $policy['safety_level'] ?? 'safe',
                'allowed_tags' => $policy['allowed_tags'] ?? config('nuclei.safe_template_tags', []),
                'blocked_tags' => $policy['blocked_tags'] ?? config('nuclei.blocked_template_tags', []),
                'reason' => $policy['reason'] ?? null,
            ]);
        }

        return null;
    }

    /**
     * @return array{allowed: false, safety_level: string, allowed_tags: list<string>, blocked_tags: list<string>, reason: string}
     */
    private function deny(string $reason): array
    {
        return [
            'allowed' => false,
            'safety_level' => 'blocked',
            'allowed_tags' => [],
            'blocked_tags' => (array) config('nuclei.blocked_template_tags', []),
            'reason' => $reason,
        ];
    }
}
