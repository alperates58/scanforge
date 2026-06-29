<?php

namespace App\Support;

final class VerificationStatuses
{
    public const PENDING = 'pending';
    public const CHECKING = 'checking';
    public const VERIFIED = 'verified';
    public const FAILED = 'failed';
    public const EXPIRED = 'expired';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            self::PENDING,
            self::CHECKING,
            self::VERIFIED,
            self::FAILED,
            self::EXPIRED,
        ];
    }
}
