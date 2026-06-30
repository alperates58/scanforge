<?php

namespace App\Scanners\Native;

use App\Models\DnsRecord;
use App\Models\ScanJob;
use Illuminate\Support\Carbon;

class DnsSecurityScanner extends AbstractNativeScanner
{
    public function scannerKey(): string
    {
        return 'dns_security';
    }

    protected function performChecks(ScanJob $scanJob): array
    {
        $websiteId = $scanJob->website_id;
        $records = DnsRecord::query()
            ->where('website_id', $websiteId)
            ->get()
            ->groupBy('type');

        $findings = [];
        $host = $scanJob->website?->host ?? 'unknown-host';
        $affectedUrl = $scanJob->website?->url ?? 'http://' . $host;

        $txtRecords = $records->get('TXT', collect());
        
        // SPF Check
        $spfRecords = $txtRecords->filter(fn ($r) => str_starts_with(strtolower((string)$r->value), 'v=spf1'));
        if ($spfRecords->isEmpty()) {
            $findings[] = $this->createPayload('missing_spf', 'medium', 'Missing SPF Record', 'No Sender Policy Framework (SPF) record found, increasing risk of email spoofing.', 'CWE-358', $affectedUrl, []);
        }

        // DMARC Check
        $dmarcRecords = $txtRecords->filter(fn ($r) => str_starts_with(strtolower((string)$r->value), 'v=dmarc1'));
        if ($dmarcRecords->isEmpty()) {
            $findings[] = $this->createPayload('missing_dmarc', 'medium', 'Missing DMARC Record', 'No DMARC record found, preventing domain from enforcing email authentication policies.', 'CWE-358', $affectedUrl, []);
        } else {
            $hasWeakPolicy = false;
            foreach ($dmarcRecords as $r) {
                if (str_contains(strtolower((string)$r->value), 'p=none')) {
                    $hasWeakPolicy = true;
                    break;
                }
            }
            if ($hasWeakPolicy) {
                $findings[] = $this->createPayload('weak_dmarc_policy_none', 'low', 'Weak DMARC Policy (p=none)', 'DMARC policy is set to "none", which does not reject or quarantine unauthenticated emails.', 'CWE-358', $affectedUrl, ['record' => $dmarcRecords->first()?->value]);
            }
        }

        // MX Check
        $mxRecords = $records->get('MX', collect());
        if ($mxRecords->isEmpty()) {
             $findings[] = $this->createPayload('missing_mx', 'info', 'Missing MX Records', 'No Mail Exchange (MX) records found for the domain.', 'CWE-358', $affectedUrl, []);
        }

        // NS Check
        $nsRecords = $records->get('NS', collect());
        if ($nsRecords->count() > 4) {
             $findings[] = $this->createPayload('too_many_ns_info', 'info', 'Excessive Name Servers', 'The domain has an unusually high number of name servers configured.', 'CWE-358', $affectedUrl, ['count' => $nsRecords->count()]);
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
