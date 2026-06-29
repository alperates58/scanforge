<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Workspace extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'owner_user_id',
        'plan_name',
        'monthly_scan_limit',
        'concurrent_scan_limit',
        'scans_used_this_month',
    ];

    protected function casts(): array
    {
        return [
            'monthly_scan_limit' => 'integer',
            'concurrent_scan_limit' => 'integer',
            'scans_used_this_month' => 'integer',
        ];
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function owner(): BelongsTo
    {
        return $this->belongsTo(User::class, 'owner_user_id');
    }

    /**
     * @return BelongsToMany<User, $this>
     */
    public function members(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'workspace_members')->withPivot('role')->withTimestamps();
    }

    /**
     * @return HasMany<WorkspaceMember, $this>
     */
    public function memberships(): HasMany
    {
        return $this->hasMany(WorkspaceMember::class);
    }

    /**
     * @return HasMany<Website, $this>
     */
    public function websites(): HasMany
    {
        return $this->hasMany(Website::class);
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
    public function websiteCredentials(): HasMany
    {
        return $this->hasMany(WebsiteCredential::class);
    }
}
