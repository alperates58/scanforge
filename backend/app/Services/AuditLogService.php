<?php

namespace App\Services;

use App\Models\AuditLog;
use App\Models\User;

class AuditLogService
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function record(
        string $action,
        ?User $user = null,
        ?int $workspaceId = null,
        ?string $targetType = null,
        ?int $targetId = null,
        ?string $ipAddress = null,
        array $metadata = [],
    ): AuditLog {
        return AuditLog::query()->create([
            'workspace_id' => $workspaceId,
            'user_id' => $user?->id,
            'action' => $action,
            'target_type' => $targetType,
            'target_id' => $targetId,
            'ip_address' => $ipAddress,
            'metadata' => $this->redact($metadata),
        ]);
    }

    /**
     * @param array<string, mixed> $metadata
     * @return array<string, mixed>
     */
    private function redact(array $metadata): array
    {
        $sensitiveFragments = ['password', 'secret', 'token', 'cookie', 'authorization', 'api_key'];

        foreach ($metadata as $key => $value) {
            $lowerKey = strtolower((string) $key);

            foreach ($sensitiveFragments as $fragment) {
                if (str_contains($lowerKey, $fragment)) {
                    $metadata[$key] = '[redacted]';
                    continue 2;
                }
            }

            if (is_array($value)) {
                $metadata[$key] = $this->redact($value);
            }
        }

        return $metadata;
    }
}
