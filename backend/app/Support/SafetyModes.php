<?php

namespace App\Support;

final class SafetyModes
{
    public const SAFE = 'safe';
    public const STANDARD = 'standard';
    public const DEEP = 'deep';
    public const AUTHENTICATED = 'authenticated';

    /** @return list<string> */
    public static function all(): array
    {
        return [
            self::SAFE,
            self::STANDARD,
            self::DEEP,
            self::AUTHENTICATED,
        ];
    }
}
