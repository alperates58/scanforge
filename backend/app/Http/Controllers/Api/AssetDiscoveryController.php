<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Concerns\RespondsWithJson;
use App\Http\Controllers\Controller;
use App\Models\AssetDiscovery;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\AssetDiscoveryService;
use App\Services\AuditLogService;
use App\Services\WorkspaceContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AssetDiscoveryController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private readonly WorkspaceContext $workspaceContext,
        private readonly AssetDiscoveryService $assetDiscoveryService,
        private readonly AuditLogService $auditLogService,
    ) {
    }

    public function store(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);
        $discovery = $this->assetDiscoveryService->run($website);

        $this->auditLogService->record(
            'asset_discovery.completed',
            $request->user(),
            $workspace->id,
            'asset_discovery',
            $discovery->id,
            $request->ip(),
            [
                'website_id' => $website->id,
                'status' => $discovery->status,
                'discovery_score' => $discovery->discovery_score,
            ],
        );

        return $this->ok($this->assetDiscoveryService->discoveryData($discovery), 202);
    }

    public function index(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        $discoveries = AssetDiscovery::query()
            ->where('website_id', $website->id)
            ->latest()
            ->limit(25)
            ->get()
            ->map(fn (AssetDiscovery $discovery): array => $this->assetDiscoveryService->discoveryData($discovery))
            ->values()
            ->all();

        return $this->ok($discoveries);
    }

    public function show(Request $request, int $website, int $discovery): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);
        $discovery = AssetDiscovery::query()
            ->where('website_id', $website->id)
            ->whereKey($discovery)
            ->firstOrFail();

        return $this->ok($this->assetDiscoveryService->discoveryData($discovery));
    }

    private function findWebsite(int $websiteId, Workspace $workspace): Website
    {
        return Website::query()
            ->where('workspace_id', $workspace->id)
            ->whereKey($websiteId)
            ->firstOrFail();
    }
}
