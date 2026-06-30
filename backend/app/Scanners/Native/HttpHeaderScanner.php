<?php

namespace App\Scanners\Native;

use App\Models\HttpObservation;
use App\Models\ScanJob;
use Illuminate\Support\Carbon;

class HttpHeaderScanner extends AbstractNativeScanner
{
    public function scannerKey(): string
    {
        return 'http_headers';
    }

    protected function performChecks(ScanJob $scanJob): array
    {
        $websiteId = $scanJob->website_id;
        $observations = HttpObservation::query()
            ->with(['securityHeaders'])
            ->where('website_id', $websiteId)
            ->latest('observed_at')
            ->get();

        $findings = [];
        $analyzedUrls = [];

        foreach ($observations as $obs) {
            // Process each URL only once
            $url = $obs->final_url ?: $obs->url;
            if (isset($analyzedUrls[$url])) {
                continue;
            }
            $analyzedUrls[$url] = true;

            $headers = $obs->securityHeaders->keyBy('header_key');
            
            if (! $headers->has('strict-transport-security') || ! $headers->get('strict-transport-security')->present) {
                $findings[] = $this->createPayload('missing_hsts', 'medium', 'Missing HSTS Header', 'HTTP Strict Transport Security (HSTS) header is missing, allowing downgrade attacks.', 'CWE-319', $url, []);
            }

            if (! $headers->has('content-security-policy') || ! $headers->get('content-security-policy')->present) {
                $findings[] = $this->createPayload('missing_csp', 'medium', 'Missing Content-Security-Policy', 'Content Security Policy (CSP) header is missing, increasing risk of Cross-Site Scripting (XSS).', 'CWE-693', $url, []);
            }

            if (! $headers->has('x-frame-options') || ! $headers->get('x-frame-options')->present) {
                if (! $headers->has('content-security-policy') || ! str_contains(strtolower((string)$headers->get('content-security-policy')->value), 'frame-ancestors')) {
                     $findings[] = $this->createPayload('missing_x_frame_options', 'low', 'Missing X-Frame-Options', 'X-Frame-Options header is missing, increasing risk of clickjacking attacks.', 'CWE-1021', $url, []);
                }
            }

            if (! $headers->has('x-content-type-options') || ! $headers->get('x-content-type-options')->present) {
                $findings[] = $this->createPayload('missing_x_content_type_options', 'low', 'Missing X-Content-Type-Options', 'X-Content-Type-Options header is missing, allowing MIME sniffing attacks.', 'CWE-693', $url, []);
            }

            if ($obs->server_header) {
                 $findings[] = $this->createPayload('server_version_exposure', 'info', 'Server Version Exposure', 'The Server HTTP header exposes the server software and version.', 'CWE-200', $url, ['header' => 'Server', 'value' => $obs->server_header]);
            }

            if ($obs->powered_by_header) {
                 $findings[] = $this->createPayload('x_powered_by_exposure', 'info', 'X-Powered-By Header Exposure', 'The X-Powered-By HTTP header exposes backend technology details.', 'CWE-200', $url, ['header' => 'X-Powered-By', 'value' => $obs->powered_by_header]);
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
            'timestamp' => Carbon::now()->toIso8601String(),
        ];
    }
}
