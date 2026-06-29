<?php

namespace App\Support;

final class WebsiteEnums
{
    public const ENVIRONMENT_PRODUCTION = 'production';
    public const ENVIRONMENT_STAGING = 'staging';
    public const ENVIRONMENT_DEVELOPMENT = 'development';
    public const ENVIRONMENT_OTHER = 'other';

    public const IMPORTANCE_LOW = 'low';
    public const IMPORTANCE_NORMAL = 'normal';
    public const IMPORTANCE_HIGH = 'high';
    public const IMPORTANCE_CRITICAL = 'critical';

    /**
     * @return list<string>
     */
    public static function environments(): array
    {
        return [
            self::ENVIRONMENT_PRODUCTION,
            self::ENVIRONMENT_STAGING,
            self::ENVIRONMENT_DEVELOPMENT,
            self::ENVIRONMENT_OTHER,
        ];
    }

    /**
     * @return list<string>
     */
    public static function importanceLevels(): array
    {
        return [
            self::IMPORTANCE_LOW,
            self::IMPORTANCE_NORMAL,
            self::IMPORTANCE_HIGH,
            self::IMPORTANCE_CRITICAL,
        ];
    }
}
