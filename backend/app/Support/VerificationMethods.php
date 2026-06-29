<?php

namespace App\Support;

final class VerificationMethods
{
    public const DNS_TXT = 'dns_txt';
    public const HTML_FILE = 'html_file';
    public const META_TAG = 'meta_tag';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [
            self::DNS_TXT,
            self::HTML_FILE,
            self::META_TAG,
        ];
    }
}
