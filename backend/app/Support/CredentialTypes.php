<?php

namespace App\Support;

final class CredentialTypes
{
    public const BASIC_AUTH = 'basic_auth';
    public const BEARER_TOKEN = 'bearer_token';
    public const COOKIE = 'cookie';
    public const JWT = 'jwt';
    public const USERNAME_PASSWORD = 'username_password';
    public const CUSTOM_HEADER = 'custom_header';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            self::BASIC_AUTH,
            self::BEARER_TOKEN,
            self::COOKIE,
            self::JWT,
            self::USERNAME_PASSWORD,
            self::CUSTOM_HEADER,
        ];
    }
}
