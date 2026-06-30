<?php

namespace App\Services;

use App\Models\Finding;
use App\Models\FindingEvent;
use App\Models\FindingHistory;
use App\Models\SuppressionRule;
use App\Models\User;
use App\Support\FindingStatuses;
use Illuminate\Support\Carbon;
use Illuminate\Validation\ValidationException;

class FindingStatusTransitionService
{
    public function __construct(
        private readonly WebsiteRiskRollupService $websiteRiskRollupService,
    ) {
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function transition(
        Finding $finding,
        string $newStatus,
        ?User $user = null,
        ?string $reason = null,
        array $metadata = [],
        bool $createSuppressionRule = false,
        ?Carbon $expiresAt = null,
    ): Finding {
        if (! in_array($newStatus, FindingStatuses::all(), true)) {
            throw ValidationException::withMessages([
                'status' => ['Unsupported finding status.'],
            ]);
        }

        $oldStatus = $finding->status;
        $now = Carbon::now();
        $attributes = ['status' => $newStatus];

        if ($newStatus === FindingStatuses::RESOLVED) {
            $attributes['resolved_at'] = $now;
        }

        if ($newStatus === FindingStatuses::REOPENED) {
            $attributes['reopened_at'] = $now;
            $attributes['resolved_at'] = null;
        }

        if (in_array($newStatus, [FindingStatuses::NEW, FindingStatuses::CONFIRMED], true)) {
            $attributes['resolved_at'] = null;
        }

        $finding->forceFill($attributes)->save();
        $finding = $finding->fresh();

        $this->recordEvent($finding, $oldStatus, $newStatus, $reason, $user, $metadata);

        if ($createSuppressionRule && in_array($newStatus, [FindingStatuses::IGNORED, FindingStatuses::FALSE_POSITIVE], true)) {
            $this->createSuppressionRule($finding, $newStatus, $reason, $user, $expiresAt);
        }

        $this->websiteRiskRollupService->refresh((int) $finding->website_id);

        return $finding;
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function recordEvent(
        Finding $finding,
        ?string $oldStatus,
        string $newStatus,
        ?string $reason = null,
        ?User $user = null,
        array $metadata = [],
    ): void {
        $changedAt = Carbon::now();

        FindingEvent::query()->create([
            'finding_id' => $finding->id,
            'workspace_id' => $finding->workspace_id,
            'website_id' => $finding->website_id,
            'scan_id' => $finding->scan_id,
            'old_status' => $oldStatus,
            'new_status' => $newStatus,
            'reason' => $reason,
            'changed_by_user_id' => $user?->id,
            'metadata' => $metadata,
            'changed_at' => $changedAt,
        ]);

        FindingHistory::query()->create([
            'finding_id' => $finding->id,
            'scan_id' => $finding->scan_id,
            'from_status' => $oldStatus,
            'to_status' => $newStatus,
            'reason' => $reason,
            'metadata' => [
                ...$metadata,
                'changed_by_user_id' => $user?->id,
            ],
            'changed_at' => $changedAt,
        ]);
    }

    private function createSuppressionRule(Finding $finding, string $action, ?string $reason, ?User $user, ?Carbon $expiresAt): void
    {
        SuppressionRule::query()->create([
            'workspace_id' => $finding->workspace_id,
            'website_id' => $finding->website_id,
            'scanner_key' => $finding->scanner_key,
            'template_id' => $finding->template_id,
            'host' => parse_url((string) $finding->affected_url, PHP_URL_HOST) ?: $finding->website?->host,
            'action' => $action,
            'expires_at' => $expiresAt,
            'reason' => $reason,
            'created_by_user_id' => $user?->id,
            'enabled' => true,
            'metadata' => [
                'finding_id' => $finding->id,
                'correlation_key' => $finding->correlation_key,
            ],
        ]);
    }
}
