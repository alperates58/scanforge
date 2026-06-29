<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class AssetDiscovery extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'website_id',
        'scan_id',
        'status',
        'started_at',
        'dns_completed_at',
        'http_completed_at',
        'ssl_completed_at',
        'whois_completed_at',
        'completed_at',
        'duration_ms',
        'summary',
        'error_message',
        'total_dns_records',
        'total_ips',
        'total_headers',
        'total_cookies',
        'total_findings',
        'technologies_detected',
        'analysis_required',
        'discovery_score',
    ];

    protected function casts(): array
    {
        return [
            'started_at' => 'datetime',
            'dns_completed_at' => 'datetime',
            'http_completed_at' => 'datetime',
            'ssl_completed_at' => 'datetime',
            'whois_completed_at' => 'datetime',
            'completed_at' => 'datetime',
            'duration_ms' => 'integer',
            'summary' => 'array',
            'total_dns_records' => 'integer',
            'total_ips' => 'integer',
            'total_headers' => 'integer',
            'total_cookies' => 'integer',
            'total_findings' => 'integer',
            'technologies_detected' => 'integer',
            'analysis_required' => 'boolean',
            'discovery_score' => 'integer',
        ];
    }

    /** @return BelongsTo<Workspace, $this> */
    public function workspace(): BelongsTo
    {
        return $this->belongsTo(Workspace::class);
    }

    /** @return BelongsTo<Website, $this> */
    public function website(): BelongsTo
    {
        return $this->belongsTo(Website::class);
    }

    /** @return BelongsTo<Scan, $this> */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    /** @return HasMany<DnsRecord, $this> */
    public function dnsRecords(): HasMany
    {
        return $this->hasMany(DnsRecord::class);
    }

    /** @return HasMany<IpAddress, $this> */
    public function ipAddresses(): HasMany
    {
        return $this->hasMany(IpAddress::class);
    }

    /** @return HasMany<HttpObservation, $this> */
    public function httpObservations(): HasMany
    {
        return $this->hasMany(HttpObservation::class);
    }

    /** @return HasMany<SslCertificate, $this> */
    public function sslCertificates(): HasMany
    {
        return $this->hasMany(SslCertificate::class);
    }

    /** @return HasMany<Subdomain, $this> */
    public function subdomains(): HasMany
    {
        return $this->hasMany(Subdomain::class);
    }

    /** @return HasMany<DomainWhoisSnapshot, $this> */
    public function whoisSnapshots(): HasMany
    {
        return $this->hasMany(DomainWhoisSnapshot::class);
    }

    /** @return HasMany<Finding, $this> */
    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class);
    }

    /** @return HasMany<TechnologyFingerprint, $this> */
    public function technologyFingerprints(): HasMany
    {
        return $this->hasMany(TechnologyFingerprint::class);
    }

    /** @return HasMany<ScanPlan, $this> */
    public function scanPlans(): HasMany
    {
        return $this->hasMany(ScanPlan::class);
    }
}
