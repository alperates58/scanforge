<?php

namespace App\Services;

use App\Models\AssetDiscovery;
use App\Models\DomainWhoisSnapshot;
use App\Models\Website;
use Illuminate\Support\Carbon;

class WhoisLookupService
{
    public function discover(Website $website, AssetDiscovery $discovery): DomainWhoisSnapshot
    {
        $now = Carbon::now();
        $data = $this->lookup((string) $website->root_domain);

        return DomainWhoisSnapshot::query()->create([
            'workspace_id' => $website->workspace_id,
            'website_id' => $website->id,
            'asset_discovery_id' => $discovery->id,
            'registrar' => $data['registrar'],
            'created_at_remote' => $data['created_at_remote'],
            'expires_at_remote' => $data['expires_at_remote'],
            'updated_at_remote' => $data['updated_at_remote'],
            'age_days' => $data['age_days'],
            'raw_summary' => $data['raw_summary'],
            'observed_at' => $now,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function lookup(string $domain): array
    {
        if (! (bool) config('scanforge.discovery.whois_enabled', false)) {
            return $this->unavailable('disabled');
        }

        $raw = $this->queryWhois('whois.iana.org', $domain);

        if ($raw === null) {
            return $this->unavailable('iana_unavailable');
        }

        $registrarServer = null;

        if (preg_match('/whois:\s*(\S+)/i', $raw, $matches) === 1) {
            $registrarServer = trim($matches[1]);
        }

        $registrarRaw = $registrarServer ? $this->queryWhois($registrarServer, $domain) : null;
        $text = $registrarRaw ?? $raw;
        $createdAt = $this->dateField($text, ['creation date', 'created on', 'created']);
        $expiresAt = $this->dateField($text, ['registry expiry date', 'expiration date', 'expires on', 'paid-till']);
        $updatedAt = $this->dateField($text, ['updated date', 'last updated']);

        return [
            'registrar' => $this->textField($text, ['registrar']),
            'created_at_remote' => $createdAt,
            'expires_at_remote' => $expiresAt,
            'updated_at_remote' => $updatedAt,
            'age_days' => $createdAt ? $createdAt->diffInDays(Carbon::now()) : null,
            'raw_summary' => [
                'status' => 'available',
                'source' => $registrarServer ?? 'whois.iana.org',
                'sample' => substr($text, 0, 1000),
            ],
        ];
    }

    private function queryWhois(string $server, string $domain): ?string
    {
        $socket = @stream_socket_client(
            'tcp://'.$server.':43',
            $errno,
            $errstr,
            (int) config('scanforge.discovery.timeout_seconds', 5)
        );

        if (! is_resource($socket)) {
            return null;
        }

        fwrite($socket, $domain."\r\n");
        stream_set_timeout($socket, (int) config('scanforge.discovery.timeout_seconds', 5));
        $response = stream_get_contents($socket);
        fclose($socket);

        return is_string($response) && $response !== '' ? $response : null;
    }

    /**
     * @param list<string> $fields
     */
    private function dateField(string $text, array $fields): ?Carbon
    {
        foreach ($fields as $field) {
            if (preg_match('/^'.preg_quote($field, '/').'\s*:\s*(.+)$/im', $text, $matches) === 1) {
                $timestamp = strtotime(trim($matches[1]));

                return $timestamp === false ? null : Carbon::createFromTimestamp($timestamp);
            }
        }

        return null;
    }

    /**
     * @param list<string> $fields
     */
    private function textField(string $text, array $fields): ?string
    {
        foreach ($fields as $field) {
            if (preg_match('/^'.preg_quote($field, '/').'\s*:\s*(.+)$/im', $text, $matches) === 1) {
                return trim($matches[1]);
            }
        }

        return null;
    }

    /**
     * @return array<string, mixed>
     */
    private function unavailable(string $reason): array
    {
        return [
            'registrar' => null,
            'created_at_remote' => null,
            'expires_at_remote' => null,
            'updated_at_remote' => null,
            'age_days' => null,
            'raw_summary' => [
                'status' => 'unavailable',
                'reason' => $reason,
            ],
        ];
    }
}
