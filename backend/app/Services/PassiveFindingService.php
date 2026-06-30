<?php

namespace App\Services;

use App\Models\AssetDiscovery;
use App\Models\Finding;
use App\Models\HttpObservation;
use App\Models\SslCertificate;
use App\Models\Website;

class PassiveFindingService
{
    public function __construct(
        private readonly FindingNormalizationService $findingNormalizationService,
    ) {
    }

    /**
     * @param list<string> $privateIps
     */
    public function privateIpResolution(Website $website, AssetDiscovery $discovery, array $privateIps): int
    {
        if ($privateIps === []) {
            return 0;
        }

        $this->upsert($website, $discovery, [
            'title' => 'Domain resolves to private or reserved IP address',
            'severity' => 'high',
            'evidence' => 'DNS resolution returned private/reserved IP addresses: '.implode(', ', $privateIps),
            'remediation' => 'Confirm the domain is intended to resolve publicly before allowing discovery or scanning.',
            'metadata' => ['private_ips' => $privateIps, 'category' => 'target_safety'],
        ]);

        return 1;
    }

    /**
     * @param array<string, array{present: bool, value: string|null, recommendation: string}> $securityHeaders
     * @param list<array<string, mixed>> $cookies
     * @param array{available: bool, status_code: int|null, sensitive_paths: list<string>} $robots
     */
    public function httpFindings(Website $website, AssetDiscovery $discovery, HttpObservation $observation, array $securityHeaders, array $cookies, array $robots): int
    {
        $count = 0;

        foreach ([
            'hsts' => ['Missing HSTS header', 'medium'],
            'csp' => ['Missing Content-Security-Policy header', 'low'],
            'x_frame_options' => ['Missing X-Frame-Options header', 'low'],
            'x_content_type_options' => ['Missing X-Content-Type-Options header', 'low'],
        ] as $key => [$title, $severity]) {
            if (! ($securityHeaders[$key]['present'] ?? false)) {
                $this->upsert($website, $discovery, [
                    'title' => $title,
                    'severity' => $severity,
                    'evidence' => $securityHeaders[$key]['recommendation'] ?? 'Header was not observed in the response.',
                    'remediation' => 'Add the header after validating compatibility with the application.',
                    'metadata' => ['header_key' => $key, 'category' => 'security_headers'],
                ]);
                $count++;
            }
        }

        foreach ([
            'secure' => ['Cookie missing Secure flag', 'Set Secure on cookies that must only travel over HTTPS.'],
            'http_only' => ['Cookie missing HttpOnly flag', 'Set HttpOnly on cookies that do not need JavaScript access.'],
            'same_site' => ['Cookie missing SameSite attribute', 'Set SameSite according to the application flow.'],
        ] as $attribute => [$title, $remediation]) {
            $affectedCookies = array_values(array_filter($cookies, fn (array $cookie): bool => $attribute === 'same_site'
                ? ! $cookie['same_site']
                : ! $cookie[$attribute]));

            if ($affectedCookies === []) {
                continue;
            }

            $this->upsert($website, $discovery, [
                'title' => $title,
                'severity' => 'low',
                'evidence' => 'Affected cookies: '.implode(', ', array_map(fn (array $cookie): string => (string) $cookie['name'], $affectedCookies)),
                'remediation' => $remediation,
                'metadata' => [
                    'attribute' => $attribute,
                    'cookies' => array_map(fn (array $cookie): array => [
                        'name' => $cookie['name'],
                        'secure' => $cookie['secure'],
                        'http_only' => $cookie['http_only'],
                        'same_site' => $cookie['same_site'],
                    ], $affectedCookies),
                    'category' => 'cookies',
                ],
            ]);
            $count++;
        }

        if ($observation->server_header && preg_match('/\/\d+(?:\.\d+)+/', $observation->server_header) === 1) {
            $this->upsert($website, $discovery, [
                'title' => 'Server header exposes version information',
                'severity' => 'info',
                'evidence' => 'Observed Server header: '.$observation->server_header,
                'remediation' => 'Reduce version detail in public server headers where operationally possible.',
                'metadata' => ['server_header' => $observation->server_header, 'category' => 'headers'],
            ]);
            $count++;
        }

        if ($observation->powered_by_header) {
            $this->upsert($website, $discovery, [
                'title' => 'X-Powered-By header exposes technology information',
                'severity' => 'info',
                'evidence' => 'Observed X-Powered-By header: '.$observation->powered_by_header,
                'remediation' => 'Remove or minimize X-Powered-By if it is not required.',
                'metadata' => ['powered_by_header' => $observation->powered_by_header, 'category' => 'headers'],
            ]);
            $count++;
        }

        if (($robots['sensitive_paths'] ?? []) !== []) {
            $this->upsert($website, $discovery, [
                'title' => 'robots.txt references sensitive-looking paths',
                'severity' => 'info',
                'evidence' => 'robots.txt listed sensitive-looking disallow entries. ScanForge did not request those paths.',
                'remediation' => 'Review whether robots.txt discloses operationally sensitive routes.',
                'metadata' => ['paths' => $robots['sensitive_paths'], 'category' => 'robots'],
            ]);
            $count++;
        }

        return $count;
    }

    public function sslFindings(Website $website, AssetDiscovery $discovery, ?SslCertificate $certificate): int
    {
        if ($certificate === null || $certificate->days_remaining === null) {
            return 0;
        }

        if ($certificate->days_remaining < 0) {
            $this->upsert($website, $discovery, [
                'title' => 'SSL certificate is expired',
                'severity' => 'high',
                'evidence' => 'Certificate expired '.$certificate->days_remaining.' days ago.',
                'remediation' => 'Renew and deploy a valid TLS certificate.',
                'metadata' => ['days_remaining' => $certificate->days_remaining, 'category' => 'ssl'],
            ]);

            return 1;
        }

        if ($certificate->days_remaining <= 14) {
            $this->upsert($website, $discovery, [
                'title' => 'SSL certificate expires soon',
                'severity' => 'medium',
                'evidence' => 'Certificate expires in '.$certificate->days_remaining.' days.',
                'remediation' => 'Renew the TLS certificate before expiry.',
                'metadata' => ['days_remaining' => $certificate->days_remaining, 'category' => 'ssl'],
            ]);

            return 1;
        }

        return 0;
    }

    /**
     * @param array{title: string, severity: string, evidence: string, remediation: string, metadata: array<string, mixed>} $data
     */
    private function upsert(Website $website, AssetDiscovery $discovery, array $data): Finding
    {
        return $this->findingNormalizationService->persistPassiveFinding($website, $discovery, $data);
    }
}
