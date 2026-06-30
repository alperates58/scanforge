<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Concerns\RespondsWithJson;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\StoreWebsiteRequest;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\AuditLogService;
use App\Services\DomainVerificationService;
use App\Services\TargetUrlGuard;
use App\Services\WorkspaceContext;
use App\Support\VerificationStatuses;
use App\Support\WebsiteEnums;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class WebsiteController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private readonly WorkspaceContext $workspaceContext,
        private readonly TargetUrlGuard $targetUrlGuard,
        private readonly DomainVerificationService $verificationService,
        private readonly AuditLogService $auditLogService,
    ) {
    }

    public function index(Request $request): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);

        $websites = Website::query()
            ->where('workspace_id', $workspace->id)
            ->latest()
            ->get()
            ->map(fn (Website $website): array => $this->websiteData($website))
            ->values();

        return $this->ok($websites->all(), meta: [
            'workspace_id' => $workspace->id,
        ]);
    }

    public function store(StoreWebsiteRequest $request): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $normalized = $this->targetUrlGuard->normalizeAndValidate($request->string('url')->toString());

        $exists = Website::query()
            ->where('workspace_id', $workspace->id)
            ->where('normalized_host', $normalized['normalized_host'])
            ->exists();

        if ($exists) {
            throw ValidationException::withMessages([
                'url' => ['This website host already exists in the current workspace.'],
            ]);
        }

        $website = Website::query()->create([
            'workspace_id' => $workspace->id,
            'created_by_user_id' => $request->user()->id,
            'url' => $normalized['url'],
            'scheme' => $normalized['scheme'],
            'host' => $normalized['host'],
            'root_domain' => $normalized['root_domain'],
            'port' => $normalized['port'],
            'normalized_host' => $normalized['normalized_host'],
            'status' => 'pending_verification',
            'environment' => $request->input('environment', WebsiteEnums::ENVIRONMENT_PRODUCTION),
            'importance' => $request->input('importance', WebsiteEnums::IMPORTANCE_NORMAL),
            'verification_status' => VerificationStatuses::PENDING,
            'metadata' => [
                'created_from' => 'phase02_api',
            ],
            'notes' => $request->input('notes'),
            'tags' => $request->input('tags', []),
        ]);

        $verification = $this->verificationService->instructions($website->fresh(['domainVerifications']));

        $this->auditLogService->record(
            'website.created',
            $request->user(),
            $workspace->id,
            'website',
            $website->id,
            $request->ip(),
            [
                'normalized_host' => $website->normalized_host,
                'environment' => $website->environment,
                'importance' => $website->importance,
            ],
        );

        return $this->ok([
            'website' => $this->websiteData($website->fresh()),
            'verification' => $verification,
        ], 201);
    }

    public function show(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->websiteData($website));
    }

    public function destroy(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        $websiteId = $website->id;
        $website->delete();

        $this->auditLogService->record(
            'website.deleted',
            $request->user(),
            $workspace->id,
            'website',
            $websiteId,
            $request->ip(),
        );

        return $this->ok([
            'deleted' => true,
        ]);
    }

    private function findWebsite(int $websiteId, Workspace $workspace): Website
    {
        return Website::query()
            ->where('workspace_id', $workspace->id)
            ->whereKey($websiteId)
            ->firstOrFail();
    }

    /**
     * @return array<string, mixed>
     */
    private function websiteData(Website $website): array
    {
        return [
            'id' => $website->id,
            'workspace_id' => $website->workspace_id,
            'url' => $website->url,
            'scheme' => $website->scheme,
            'host' => $website->host,
            'root_domain' => $website->root_domain,
            'normalized_host' => $website->normalized_host,
            'environment' => $website->environment,
            'importance' => $website->importance,
            'status' => $website->status,
            'verification_status' => $website->verification_status,
            'verification_method' => $website->verification_method,
            'verification_last_checked_at' => $website->verification_last_checked_at?->toISOString(),
            'ownership_verified_at' => $website->ownership_verified_at?->toISOString(),
            'verified_at' => $website->verified_at?->toISOString(),
            'security_score' => $website->security_score,
            'risk_score' => $website->risk_score,
            'critical_count' => $website->critical_count,
            'high_count' => $website->high_count,
            'risk_trend' => $website->risk_trend,
            'last_scan_score' => $website->last_scan_score,
            'last_scan_at' => $website->last_scan_at?->toISOString(),
            'discovery_completed_at' => $website->discovery_completed_at?->toISOString(),
            'last_observed_at' => $website->last_observed_at?->toISOString(),
            'notes' => $website->notes,
            'tags' => $website->tags ?? [],
            'created_at' => $website->created_at?->toISOString(),
        ];
    }
}
