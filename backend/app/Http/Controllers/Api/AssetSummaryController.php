<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Concerns\RespondsWithJson;
use App\Http\Controllers\Controller;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\AssetDiscoveryService;
use App\Services\WorkspaceContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AssetSummaryController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private readonly WorkspaceContext $workspaceContext,
        private readonly AssetDiscoveryService $assetDiscoveryService,
    ) {
    }

    public function __invoke(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->assetDiscoveryService->summary($website));
    }

    private function findWebsite(int $websiteId, Workspace $workspace): Website
    {
        return Website::query()
            ->where('workspace_id', $workspace->id)
            ->whereKey($websiteId)
            ->firstOrFail();
    }
}
