<?php

namespace App\Support;

final class QueueNames
{
    public const SCAN_HIGH = 'scan-high';
    public const SCAN_NORMAL = 'scan-normal';
    public const SCAN_LOW = 'scan-low';
    public const MAINTENANCE = 'maintenance';
    public const AI = 'ai';
    public const NOTIFICATION = 'notification';

    public static function forPriority(int $priority): string
    {
        if ($priority >= 80) {
            return self::SCAN_HIGH;
        }

        if ($priority <= 30) {
            return self::SCAN_LOW;
        }

        return self::SCAN_NORMAL;
    }
}
