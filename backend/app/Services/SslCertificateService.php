<?php

namespace App\Services;

use App\Models\AssetDiscovery;
use App\Models\SslCertificate;
use App\Models\Website;
use Illuminate\Support\Carbon;

class SslCertificateService
{
    public function discover(Website $website, AssetDiscovery $discovery): SslCertificate
    {
        $now = Carbon::now();
        $data = $this->fetchCertificate((string) $website->host);

        return SslCertificate::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'asset_discovery_id' => $discovery->id,
            'host' => $website->host,
            'issuer' => $data['issuer'],
            'subject' => $data['subject'],
            'valid_from' => $data['valid_from'],
            'valid_to' => $data['valid_to'],
            'days_remaining' => $data['days_remaining'],
            'san' => $data['san'],
            'fingerprint_sha256' => $data['fingerprint_sha256'],
            'tls_summary' => $data['tls_summary'],
            'observed_at' => $now,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function fetchCertificate(string $host): array
    {
        $default = [
            'issuer' => null,
            'subject' => null,
            'valid_from' => null,
            'valid_to' => null,
            'days_remaining' => null,
            'san' => [],
            'fingerprint_sha256' => null,
            'tls_summary' => [
                'available' => false,
                'source' => 'php_openssl',
            ],
        ];

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'SNI_enabled' => true,
                'peer_name' => $host,
            ],
        ]);

        $client = @stream_socket_client(
            'ssl://'.$host.':443',
            $errno,
            $errstr,
            (int) config('scanforge.discovery.timeout_seconds', 5),
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (! is_resource($client)) {
            $default['tls_summary']['error'] = $errstr ?: 'ssl_connection_failed';

            return $default;
        }

        $params = stream_context_get_params($client);
        fclose($client);
        $certificate = $params['options']['ssl']['peer_certificate'] ?? null;

        if (! $certificate) {
            $default['tls_summary']['error'] = 'certificate_unavailable';

            return $default;
        }

        $parsed = openssl_x509_parse($certificate);

        if (! is_array($parsed)) {
            $default['tls_summary']['error'] = 'certificate_parse_failed';

            return $default;
        }

        $validFrom = isset($parsed['validFrom_time_t']) ? Carbon::createFromTimestamp((int) $parsed['validFrom_time_t']) : null;
        $validTo = isset($parsed['validTo_time_t']) ? Carbon::createFromTimestamp((int) $parsed['validTo_time_t']) : null;
        $san = $this->subjectAltNames((string) ($parsed['extensions']['subjectAltName'] ?? ''));

        return [
            'issuer' => json_encode($parsed['issuer'] ?? [], JSON_UNESCAPED_SLASHES),
            'subject' => json_encode($parsed['subject'] ?? [], JSON_UNESCAPED_SLASHES),
            'valid_from' => $validFrom,
            'valid_to' => $validTo,
            'days_remaining' => $validTo?->diffInDays(Carbon::now(), false) !== null ? Carbon::now()->diffInDays($validTo, false) : null,
            'san' => $san,
            'fingerprint_sha256' => openssl_x509_fingerprint($certificate, 'sha256') ?: null,
            'tls_summary' => [
                'available' => true,
                'source' => 'php_openssl',
            ],
        ];
    }

    /**
     * @return list<string>
     */
    private function subjectAltNames(string $extension): array
    {
        if ($extension === '') {
            return [];
        }

        $names = [];

        foreach (explode(',', $extension) as $part) {
            $part = trim($part);

            if (str_starts_with($part, 'DNS:')) {
                $names[] = strtolower(substr($part, 4));
            }
        }

        return array_values(array_unique($names));
    }
}
