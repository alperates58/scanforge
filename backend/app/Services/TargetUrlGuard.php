<?php

namespace App\Services;

use Illuminate\Validation\ValidationException;

class TargetUrlGuard
{
    private const BLOCKED_SUFFIXES = [
        '.localhost',
        '.local',
        '.internal',
        '.intranet',
        '.lan',
    ];

    private const MULTI_LABEL_SUFFIXES = [
        'com.tr',
        'net.tr',
        'org.tr',
        'edu.tr',
        'gov.tr',
        'co.uk',
        'org.uk',
        'ac.uk',
        'gov.uk',
    ];

    public function __construct(private readonly DnsResolver $dnsResolver)
    {
    }

    /**
     * @return array{url: string, scheme: string, host: string, normalized_host: string, root_domain: string, port: int|null}
     */
    public function normalizeAndValidate(string $input): array
    {
        $candidate = trim($input);

        if ($candidate === '') {
            $this->reject('url', 'Website URL is required.');
        }

        if (! preg_match('#^[a-z][a-z0-9+\-.]*://#i', $candidate)) {
            $candidate = 'https://'.$candidate;
        }

        $parts = parse_url($candidate);

        if (! is_array($parts)) {
            $this->reject('url', 'Website URL is not valid.');
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));

        if (! in_array($scheme, ['http', 'https'], true)) {
            $this->reject('url', 'Only http and https URLs are allowed.');
        }

        if (($parts['user'] ?? null) !== null || ($parts['pass'] ?? null) !== null) {
            $this->reject('url', 'URLs with embedded credentials are not allowed.');
        }

        $host = $this->normalizeHost((string) ($parts['host'] ?? ''));

        if ($host === '') {
            $this->reject('url', 'Website URL must include a host.');
        }

        $this->assertPublicHost($host);

        $port = isset($parts['port']) ? (int) $parts['port'] : null;

        if ($port !== null && ($port < 1 || $port > 65535)) {
            $this->reject('url', 'URL port is outside the valid range.');
        }

        $defaultPort = ($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80);
        $storedPort = $defaultPort ? null : $port;
        $hostWithPort = $storedPort === null ? $host : $host.':'.$storedPort;

        return [
            'url' => $scheme.'://'.$hostWithPort,
            'scheme' => $scheme,
            'host' => $host,
            'normalized_host' => $hostWithPort,
            'root_domain' => $this->rootDomain($host),
            'port' => $storedPort,
        ];
    }

    public function assertPublicHost(string $host): void
    {
        $host = $this->normalizeHost($host);

        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            $this->reject('url', 'Localhost targets are not allowed.');
        }

        foreach (self::BLOCKED_SUFFIXES as $suffix) {
            if (str_ends_with($host, $suffix)) {
                $this->reject('url', 'Internal hostnames are not allowed.');
            }
        }

        if (! filter_var($host, FILTER_VALIDATE_IP) && ! str_contains($host, '.')) {
            $this->reject('url', 'Single-label internal hostnames are not allowed.');
        }

        $ips = $this->dnsResolver->resolveIps($host);

        foreach ($ips as $ip) {
            if (! $this->isPublicIp($ip)) {
                $this->reject('url', 'Private, reserved, loopback and metadata IP targets are not allowed.');
            }
        }
    }

    private function normalizeHost(string $host): string
    {
        $host = trim(strtolower($host), " \t\n\r\0\x0B.");

        if (function_exists('idn_to_ascii') && $host !== '' && ! filter_var($host, FILTER_VALIDATE_IP)) {
            $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);

            if (is_string($ascii) && $ascii !== '') {
                return strtolower($ascii);
            }
        }

        return $host;
    }

    private function isPublicIp(string $ip): bool
    {
        return (bool) filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    private function rootDomain(string $host): string
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }

        $labels = explode('.', $host);

        if (count($labels) <= 2) {
            return $host;
        }

        $lastTwo = implode('.', array_slice($labels, -2));
        $lastThree = implode('.', array_slice($labels, -3));

        foreach (self::MULTI_LABEL_SUFFIXES as $suffix) {
            if ($lastTwo === $suffix) {
                return $lastThree;
            }
        }

        return $lastTwo;
    }

    private function reject(string $field, string $message): never
    {
        throw ValidationException::withMessages([
            $field => [$message],
        ]);
    }
}
