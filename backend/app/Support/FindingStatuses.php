<?php

namespace App\Support;

final class FindingStatuses
{
    public const NEW = 'new';
    public const CONFIRMED = 'confirmed';
    public const IGNORED = 'ignored';
    public const RESOLVED = 'resolved';
    public const FALSE_POSITIVE = 'false_positive';
    public const REOPENED = 'reopened';
    public const OPEN = 'open';

    /** @return list<string> */
    public static function all(): array
    {
        return [
            self::NEW,
            self::CONFIRMED,
            self::IGNORED,
            self::RESOLVED,
            self::FALSE_POSITIVE,
            self::REOPENED,
            self::OPEN,
        ];
    }

    /** @return list<string> */
    public static function active(): array
    {
        return [
            self::NEW,
            self::CONFIRMED,
            self::REOPENED,
            self::OPEN,
        ];
    }

    /** @return list<string> */
    public static function terminal(): array
    {
        return [
            self::IGNORED,
            self::RESOLVED,
            self::FALSE_POSITIVE,
        ];
    }
}
