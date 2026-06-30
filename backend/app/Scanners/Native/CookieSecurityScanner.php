<?php

namespace App\Scanners\Native;

use App\Models\CookieObservation;
use App\Models\ScanJob;
use Illuminate\Support\Carbon;

class CookieSecurityScanner extends AbstractNativeScanner
{
    public function scannerKey(): string
    {
        return 'cookie_security';
    }

    protected function performChecks(ScanJob $scanJob): array
    {
        $websiteId = $scanJob->website_id;
        $cookies = CookieObservation::query()
            ->where('website_id', $websiteId)
            ->latest('observed_at')
            ->get();

        $findings = [];
        $analyzedCookies = [];
        $affectedUrl = $scanJob->website?->url ?? 'unknown-url';

        foreach ($cookies as $cookie) {
            $cookieKey = $cookie->name . ':' . $cookie->domain;
            if (isset($analyzedCookies[$cookieKey])) {
                continue;
            }
            $analyzedCookies[$cookieKey] = true;

            $evidence = ['cookie' => $cookie->name, 'domain' => $cookie->domain];

            if (! $cookie->secure) {
                $findings[] = $this->createPayload('missing_secure', 'low', 'Cookie Missing Secure Attribute', "The cookie '{$cookie->name}' is missing the Secure attribute, meaning it can be transmitted over unencrypted connections.", 'CWE-614', $affectedUrl, $evidence);
            }

            if (! $cookie->http_only) {
                $findings[] = $this->createPayload('missing_httponly', 'low', 'Cookie Missing HttpOnly Attribute', "The cookie '{$cookie->name}' is missing the HttpOnly attribute, making it accessible to client-side scripts (XSS risk).", 'CWE-1004', $affectedUrl, $evidence);
            }

            if (! $cookie->same_site || strtolower((string)$cookie->same_site) === 'none') {
                $findings[] = $this->createPayload('missing_samesite', 'info', 'Cookie Missing SameSite Attribute', "The cookie '{$cookie->name}' does not have a strict SameSite attribute, increasing risk of CSRF.", 'CWE-1275', $affectedUrl, $evidence);
            }
            
            if (str_starts_with((string)$cookie->domain, '.')) {
                $findings[] = $this->createPayload('overly_broad_domain', 'info', 'Cookie with Overly Broad Domain', "The cookie '{$cookie->name}' is scoped to a broad domain ({$cookie->domain}), making it accessible to subdomains.", 'CWE-565', $affectedUrl, $evidence);
            }
        }

        return $findings;
    }

    private function createPayload(string $checkId, string $severity, string $title, string $description, string $cwe, string $affectedUrl, array $evidence): array
    {
        return [
            'check_id' => $checkId,
            'severity' => $severity,
            'title' => $title,
            'description' => $description,
            'cwe' => $cwe,
            'affected_url' => $affectedUrl,
            'evidence' => $evidence,
            'parameter' => $evidence['cookie'] ?? null,
            'timestamp' => Carbon::now()->toIso8601String(),
        ];
    }
}
