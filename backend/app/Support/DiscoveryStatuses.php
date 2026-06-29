<?php

namespace App\Support;

final class DiscoveryStatuses
{
    public const PENDING = 'pending';
    public const RUNNING = 'running';
    public const COMPLETED = 'completed';
    public const FAILED = 'failed';
    public const TIMEOUT = 'timeout';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            self::PENDING,
            self::RUNNING,
            self::COMPLETED,
            self::FAILED,
            self::TIMEOUT,
        ];
    }
}
