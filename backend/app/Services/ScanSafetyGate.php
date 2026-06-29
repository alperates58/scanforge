<?php

namespace App\Services;

use App\Models\Scan;
use App\Models\ScanPlan;
use App\Models\Website;
use App\Models\WebsiteCredential;
use App\Models\Workspace;
use App\Support\SafetyModes;
use App\Support\ScanTypes;
use Illuminate\Support\Carbon;

class ScanSafetyGate
{
    /**
     * @return array{allowed: bool, reasons: list<string>, policy: array<string, mixed>}
     */
    public function evaluate(Website $website, string $scanType, bool $consentAccepted): array
    {
        $reasons = [];

        if (! in_array($scanType, ScanTypes::all(), true)) {
            $reasons[] = 'unsupported_scan_type';
        }

        if (! $consentAccepted) {
            $reasons[] = 'missing_authorization_consent';
        }

        if ($this->requiresVerification($scanType) && ! $website->isVerified()) {
            $reasons[] = 'domain_not_verified';
        }

        if ($this->isInCooldown($website, $scanType)) {
            $reasons[] = 'same_target_cooldown_active';
        }

        return [
            'allowed' => $reasons === [],
            'reasons' => $reasons,
            'policy' => [
                'safe_mode' => (bool) config('scanforge.scanner.safe_mode'),
                'allow_unverified_domains' => (bool) config('scanforge.scanner.allow_unverified_domains'),
                'timeout_seconds' => (int) config('scanforge.scanner.default_timeout_seconds'),
                'workspace_concurrent_limit' => (int) ($website->workspace?->concurrent_scan_limit ?? config('scanforge.rate_limits.workspace_concurrent_scans')),
            ],
        ];
    }

    /**
     * @return array{allowed: bool, reasons: list<string>, error_code: string, status_code: int, policy: array<string, mixed>}
     */
    public function evaluateStart(
        Workspace $workspace,
        Website $website,
        ?ScanPlan $scanPlan,
        string $scanType,
        string $safetyMode,
        bool $consentAccepted,
        ?int $credentialId = null,
    ): array {
        $reasons = [];

        if ($website->workspace_id !== $workspace->id) {
            $reasons[] = 'workspace_ownership_mismatch';
        }

        if (! in_array($scanType, ScanTypes::all(), true)) {
            $reasons[] = 'unsupported_scan_type';
        }

        if (! in_array($safetyMode, SafetyModes::all(), true)) {
            $reasons[] = 'unsupported_safety_mode';
        }

        if (! $consentAccepted) {
            $reasons[] = 'missing_authorization_consent';
        }

        if (! $website->isVerified()) {
            $reasons[] = 'domain_not_verified';
        }

        if ($scanPlan === null) {
            $reasons[] = 'scan_plan_required';
        } else {
            if ($scanPlan->workspace_id !== $workspace->id || $scanPlan->website_id !== $website->id) {
                $reasons[] = 'scan_plan_scope_mismatch';
            }

            if (! in_array($scanPlan->status, ['ready', 'generated'], true)) {
                $reasons[] = 'scan_plan_not_ready';
            }
        }

        if ($workspace->scans_used_this_month >= $workspace->monthly_scan_limit) {
            $reasons[] = 'quota_exceeded';
        }

        if ($this->activeScanCount($workspace) >= max(1, (int) $workspace->concurrent_scan_limit)) {
            $reasons[] = 'concurrent_scan_limit_exceeded';
        }

        if ($this->isDeepMode($scanType, $safetyMode) && ! (bool) config('scanforge.scanner.enable_deep_scan', false)) {
            $reasons[] = 'deep_scan_disabled';
        }

        if ($scanType === ScanTypes::AUTHENTICATED || $safetyMode === SafetyModes::AUTHENTICATED) {
            if ($credentialId === null) {
                $reasons[] = 'authenticated_credential_required';
            } elseif (! $this->credentialExists($workspace, $website, $credentialId)) {
                $reasons[] = 'authenticated_credential_not_available';
            }
        }

        if ($this->isInCooldown($website, $scanType)) {
            $reasons[] = 'same_target_cooldown_active';
        }

        return [
            'allowed' => $reasons === [],
            'reasons' => $reasons,
            'error_code' => $this->errorCode($reasons),
            'status_code' => $this->statusCode($reasons),
            'policy' => [
                'safe_mode' => (bool) config('scanforge.scanner.safe_mode'),
                'deep_scan_enabled' => (bool) config('scanforge.scanner.enable_deep_scan', false),
                'timeout_seconds' => (int) config('scanforge.scanner.default_timeout_seconds'),
                'workspace_monthly_scan_limit' => (int) $workspace->monthly_scan_limit,
                'workspace_scans_used_this_month' => (int) $workspace->scans_used_this_month,
                'workspace_concurrent_limit' => (int) $workspace->concurrent_scan_limit,
            ],
        ];
    }

    private function requiresVerification(string $scanType): bool
    {
        if (! (bool) config('scanforge.scanner.allow_unverified_domains')) {
            return true;
        }

        return ScanTypes::isActive($scanType);
    }

    private function isInCooldown(Website $website, string $scanType): bool
    {
        if (! in_array($scanType, [ScanTypes::STANDARD, ScanTypes::DEEP], true)) {
            return false;
        }

        $cooldownMinutes = (int) config('scanforge.rate_limits.same_target_cooldown_minutes');

        if ($cooldownMinutes <= 0) {
            return false;
        }

        return Scan::query()
            ->where('website_id', $website->id)
            ->whereIn('scan_type', [ScanTypes::STANDARD, ScanTypes::DEEP])
            ->where('created_at', '>=', Carbon::now()->subMinutes($cooldownMinutes))
            ->exists();
    }

    private function activeScanCount(Workspace $workspace): int
    {
        return Scan::query()
            ->where('workspace_id', $workspace->id)
            ->whereNotIn('status', ['completed', 'cancelled', 'failed', 'timeout'])
            ->count();
    }

    private function isDeepMode(string $scanType, string $safetyMode): bool
    {
        return $scanType === ScanTypes::DEEP || $safetyMode === SafetyModes::DEEP;
    }

    private function credentialExists(Workspace $workspace, Website $website, int $credentialId): bool
    {
        return WebsiteCredential::query()
            ->where('workspace_id', $workspace->id)
            ->where('website_id', $website->id)
            ->whereKey($credentialId)
            ->where(function ($query): void {
                $query->whereNull('expires_at')->orWhere('expires_at', '>', Carbon::now());
            })
            ->exists();
    }

    /**
     * @param list<string> $reasons
     */
    private function errorCode(array $reasons): string
    {
        if (in_array('quota_exceeded', $reasons, true)) {
            return 'quota_exceeded';
        }

        if (in_array('concurrent_scan_limit_exceeded', $reasons, true)) {
            return 'concurrent_scan_limit_exceeded';
        }

        if ($this->hasHardSafetyReason($reasons)) {
            return 'safety_gate_rejected';
        }

        if (in_array('scan_plan_required', $reasons, true) || in_array('scan_plan_not_ready', $reasons, true)) {
            return 'scan_plan_required';
        }

        return 'safety_gate_rejected';
    }

    /**
     * @param list<string> $reasons
     */
    private function statusCode(array $reasons): int
    {
        if (in_array('quota_exceeded', $reasons, true) || in_array('concurrent_scan_limit_exceeded', $reasons, true)) {
            return 429;
        }

        if ($this->hasHardSafetyReason($reasons)) {
            return 403;
        }

        if (in_array('scan_plan_required', $reasons, true) || in_array('scan_plan_not_ready', $reasons, true)) {
            return 409;
        }

        return 403;
    }

    /**
     * @param list<string> $reasons
     */
    private function hasHardSafetyReason(array $reasons): bool
    {
        return collect($reasons)->contains(fn (string $reason): bool => in_array($reason, [
            'workspace_ownership_mismatch',
            'unsupported_scan_type',
            'unsupported_safety_mode',
            'missing_authorization_consent',
            'domain_not_verified',
            'scan_plan_scope_mismatch',
            'deep_scan_disabled',
            'authenticated_credential_required',
            'authenticated_credential_not_available',
        ], true));
    }
}
