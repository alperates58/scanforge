<?php

namespace App\Support;

final class ScanJobStatuses
{
    public const PENDING = 'pending';
    public const QUEUED = 'queued';
    public const STARTING = 'starting';
    public const RUNNING = 'running';
    public const COMPLETED = 'completed';
    public const FAILED = 'failed';
    public const TIMEOUT = 'timeout';
    public const CANCELLED = 'cancelled';
    public const SKIPPED = 'skipped';

    /** @return list<string> */
    public static function terminal(): array
    {
        return [
            self::COMPLETED,
            self::FAILED,
            self::TIMEOUT,
            self::CANCELLED,
            self::SKIPPED,
        ];
    }
}
