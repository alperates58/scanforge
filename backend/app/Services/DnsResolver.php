<?php

namespace App\Services;

class DnsResolver
{
    /**
     * @param list<string> $types
     * @return list<array<string, mixed>>
     */
    public function records(string $host, array $types): array
    {
        $mask = 0;

        foreach ($types as $type) {
            $mask |= match (strtoupper($type)) {
                'A' => DNS_A,
                'AAAA' => DNS_AAAA,
                'CNAME' => DNS_CNAME,
                'MX' => DNS_MX,
                'NS' => DNS_NS,
                'TXT' => DNS_TXT,
                'CAA' => defined('DNS_CAA') ? DNS_CAA : 0,
                default => 0,
            };
        }

        if ($mask === 0) {
            return [];
        }

        $records = @dns_get_record($host, $mask);

        if ($records === false) {
            return [];
        }

        return $records;
    }

    /**
     * @return list<string>
     */
    public function resolveIps(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }

        $records = $this->records($host, ['A', 'AAAA']);

        if ($records === false) {
            return [];
        }

        $ips = [];

        foreach ($records as $record) {
            if (isset($record['ip']) && is_string($record['ip'])) {
                $ips[] = $record['ip'];
            }

            if (isset($record['ipv6']) && is_string($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }

        return array_values(array_unique($ips));
    }

    /**
     * @return list<string>
     */
    public function txtRecords(string $host): array
    {
        $records = $this->records($host, ['TXT']);

        $values = [];

        foreach ($records as $record) {
            if (isset($record['txt']) && is_string($record['txt'])) {
                $values[] = $record['txt'];
            }

            if (isset($record['entries']) && is_array($record['entries'])) {
                foreach ($record['entries'] as $entry) {
                    if (is_string($entry)) {
                        $values[] = $entry;
                    }
                }
            }
        }

        return array_values(array_unique($values));
    }
}
