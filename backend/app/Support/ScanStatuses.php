<?php

namespace App\Support;

final class ScanStatuses
{
    public const PENDING = 'pending';
    public const QUEUED = 'queued';
    public const STARTING = 'starting';
    public const RUNNING = 'running';
    public const PAUSED = 'paused';
    public const COMPLETED = 'completed';
    public const CANCELLED = 'cancelled';
    public const FAILED = 'failed';
    public const TIMEOUT = 'timeout';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            self::PENDING,
            self::QUEUED,
            self::STARTING,
            self::RUNNING,
            self::PAUSED,
            self::COMPLETED,
            self::CANCELLED,
            self::FAILED,
            self::TIMEOUT,
        ];
    }
}
