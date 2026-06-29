<?php

namespace App\Support;

final class ScanTypes
{
    public const PASSIVE = 'passive';
    public const STANDARD = 'standard';
    public const DEEP = 'deep';
    public const AUTHENTICATED = 'authenticated';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            self::PASSIVE,
            self::STANDARD,
            self::DEEP,
            self::AUTHENTICATED,
        ];
    }

    public static function isActive(string $scanType): bool
    {
        return in_array($scanType, [self::STANDARD, self::DEEP, self::AUTHENTICATED], true);
    }
}
