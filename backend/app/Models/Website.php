<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Website extends Model
{
    use HasFactory;

    protected $fillable = [
        'workspace_id',
        'created_by_user_id',
        'url',
        'scheme',
        'host',
        'root_domain',
        'port',
        'normalized_host',
        'status',
        'environment',
        'importance',
        'verification_method',
        'verification_status',
        'verification_token_hash',
        'verification_last_checked_at',
        'ownership_verified_at',
        'verified_at',
        'last_scan_at',
        'security_score',
        'risk_score',
        'critical_count',
        'high_count',
        'risk_trend',
        'last_scan_score',
        'discovery_completed_at',
        'last_observed_at',
        'metadata',
        'notes',
        'tags',
    ];

    protected function casts(): array
    {
        return [
            'port' => 'integer',
            'verification_last_checked_at' => 'datetime',
            'ownership_verified_at' => 'datetime',
            'verified_at' => 'datetime',
            'last_scan_at' => 'datetime',
            'security_score' => 'integer',
            'risk_score' => 'float',
            'critical_count' => 'integer',
            'high_count' => 'integer',
            'last_scan_score' => 'integer',
            'discovery_completed_at' => 'datetime',
            'last_observed_at' => 'datetime',
            'metadata' => 'array',
            'tags' => 'array',
        ];
    }

    public function isVerified(): bool
    {
        return $this->verification_status === 'verified'
            && $this->ownership_verified_at !== null
            && $this->verified_at !== null;
    }

    /**
     * @return BelongsTo<Workspace, $this>
     */
    public function workspace(): BelongsTo
    {
        return $this->belongsTo(Workspace::class);
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function createdBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by_user_id');
    }

    /**
     * @return HasMany<DomainVerification, $this>
     */
    public function domainVerifications(): HasMany
    {
        return $this->hasMany(DomainVerification::class);
    }

    /**
     * @return HasMany<Scan, $this>
     */
    public function scans(): HasMany
    {
        return $this->hasMany(Scan::class);
    }

    /**
     * @return HasMany<ScanProfile, $this>
     */
    public function scanProfiles(): HasMany
    {
        return $this->hasMany(ScanProfile::class);
    }

    /**
     * @return HasMany<WebsiteCredential, $this>
     */
    public function credentials(): HasMany
    {
        return $this->hasMany(WebsiteCredential::class);
    }

    /**
     * @return HasMany<Finding, $this>
     */
    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class);
    }

    /**
     * @return HasMany<TechnologyFingerprint, $this>
     */
    public function technologyFingerprints(): HasMany
    {
        return $this->hasMany(TechnologyFingerprint::class);
    }

    /**
     * @return HasMany<TechnologyEvidence, $this>
     */
    public function technologyEvidences(): HasMany
    {
        return $this->hasMany(TechnologyEvidence::class);
    }

    /**
     * @return HasMany<TechnologyRelationship, $this>
     */
    public function technologyRelationships(): HasMany
    {
        return $this->hasMany(TechnologyRelationship::class);
    }

    /**
     * @return HasMany<TechnologyConflict, $this>
     */
    public function technologyConflicts(): HasMany
    {
        return $this->hasMany(TechnologyConflict::class);
    }

    /**
     * @return HasMany<ScanPlan, $this>
     */
    public function scanPlans(): HasMany
    {
        return $this->hasMany(ScanPlan::class);
    }

    /**
     * @return HasMany<AssetDiscovery, $this>
     */
    public function assetDiscoveries(): HasMany
    {
        return $this->hasMany(AssetDiscovery::class);
    }

    /**
     * @return HasMany<DnsRecord, $this>
     */
    public function dnsRecords(): HasMany
    {
        return $this->hasMany(DnsRecord::class);
    }

    /**
     * @return HasMany<IpAddress, $this>
     */
    public function ipAddresses(): HasMany
    {
        return $this->hasMany(IpAddress::class);
    }

    /**
     * @return HasMany<HttpObservation, $this>
     */
    public function httpObservations(): HasMany
    {
        return $this->hasMany(HttpObservation::class);
    }

    /**
     * @return HasMany<SslCertificate, $this>
     */
    public function sslCertificates(): HasMany
    {
        return $this->hasMany(SslCertificate::class);
    }

    /**
     * @return HasMany<Subdomain, $this>
     */
    public function subdomains(): HasMany
    {
        return $this->hasMany(Subdomain::class);
    }
}
