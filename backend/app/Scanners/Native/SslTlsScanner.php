<?php

namespace App\Scanners\Native;

use App\Models\ScanJob;
use App\Models\SslCertificate;
use Illuminate\Support\Carbon;

class SslTlsScanner extends AbstractNativeScanner
{
    public function scannerKey(): string
    {
        return 'ssl_tls';
    }

    protected function performChecks(ScanJob $scanJob): array
    {
        $websiteId = $scanJob->website_id;
        $certificates = SslCertificate::query()
            ->where('website_id', $websiteId)
            ->latest('observed_at')
            ->get();

        $findings = [];

        foreach ($certificates as $cert) {
            $findings = array_merge($findings, $this->analyzeCertificate($cert));
        }

        return $findings;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function analyzeCertificate(SslCertificate $cert): array
    {
        $findings = [];
        $now = Carbon::now();

        if ($cert->valid_to && $cert->valid_to->isPast()) {
            $findings[] = $this->createPayload($cert, 'certificate_expired', 'high', 'SSL/TLS Certificate is Expired', 'The SSL/TLS certificate has expired, compromising the encrypted connection.', 'CWE-295');
        } elseif ($cert->valid_to && $cert->valid_to->diffInDays($now) < 14) {
            $findings[] = $this->createPayload($cert, 'certificate_expiring_soon', 'medium', 'SSL/TLS Certificate Expiring Soon', 'The SSL/TLS certificate is expiring within 14 days.', 'CWE-295');
        }

        if ($cert->issuer && (str_contains(strtolower($cert->issuer), 'self-signed') || str_contains(strtolower($cert->issuer), strtolower((string)$cert->subject)))) {
             $findings[] = $this->createPayload($cert, 'self_signed_certificate', 'high', 'Self-Signed SSL/TLS Certificate', 'The SSL/TLS certificate is self-signed, causing trust errors for users.', 'CWE-295');
        }
        
        $host = $cert->host;
        $subject = $cert->subject ?? '';
        $sans = is_array($cert->san) ? $cert->san : [];
        if ($host) {
             $matchesHost = str_contains($subject, $host);
             foreach ($sans as $san) {
                 if (str_contains((string)$san, $host)) {
                     $matchesHost = true;
                     break;
                 }
             }
             if (!$matchesHost) {
                  $findings[] = $this->createPayload($cert, 'hostname_mismatch', 'medium', 'SSL/TLS Certificate Hostname Mismatch', 'The SSL/TLS certificate does not match the requested hostname.', 'CWE-297');
             }
        }

        return $findings;
    }

    private function createPayload(SslCertificate $cert, string $checkId, string $severity, string $title, string $description, string $cwe): array
    {
        return [
            'check_id' => $checkId,
            'severity' => $severity,
            'title' => $title,
            'description' => $description,
            'cwe' => $cwe,
            'affected_url' => 'https://' . $cert->host,
            'evidence' => [
                'issuer' => $cert->issuer,
                'subject' => $cert->subject,
                'valid_to' => $cert->valid_to?->toIso8601String(),
                'san' => $cert->san,
            ],
            'timestamp' => Carbon::now()->toIso8601String(),
        ];
    }
}
