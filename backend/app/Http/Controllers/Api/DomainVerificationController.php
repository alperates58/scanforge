<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Concerns\RespondsWithJson;
use App\Http\Controllers\Controller;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\AuditLogService;
use App\Services\DomainVerificationService;
use App\Services\WorkspaceContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class DomainVerificationController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private readonly WorkspaceContext $workspaceContext,
        private readonly DomainVerificationService $verificationService,
        private readonly AuditLogService $auditLogService,
    ) {
    }

    public function show(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        $website->load('domainVerifications');

        return $this->ok([
            'website_id' => $website->id,
            'host' => $website->host,
            'verification_status' => $website->verification_status,
            ...$this->verificationService->instructions($website),
        ]);
    }

    public function check(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        $result = $this->verificationService->check($website);

        $this->auditLogService->record(
            $result['verified'] ? 'domain_verification.verified' : 'domain_verification.checked',
            $request->user(),
            $workspace->id,
            'website',
            $website->id,
            $request->ip(),
            [
                'verified' => $result['verified'],
                'verified_method' => $result['verified_method'],
                'method_statuses' => collect($result['methods'])->map(fn (array $method): array => [
                    'method' => $method['method'],
                    'status' => $method['status'],
                ])->values()->all(),
            ],
        );

        return $this->ok([
            'website_id' => $website->id,
            ...$result,
        ]);
    }

    private function findWebsite(int $websiteId, Workspace $workspace): Website
    {
        return Website::query()
            ->where('workspace_id', $workspace->id)
            ->whereKey($websiteId)
            ->firstOrFail();
    }
}
