<?php

namespace App\Support;

final class FindingSeverities
{
    public const CRITICAL = 'critical';
    public const HIGH = 'high';
    public const MEDIUM = 'medium';
    public const LOW = 'low';
    public const INFO = 'info';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            self::CRITICAL,
            self::HIGH,
            self::MEDIUM,
            self::LOW,
            self::INFO,
        ];
    }
}
