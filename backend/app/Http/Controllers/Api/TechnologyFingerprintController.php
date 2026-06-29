<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Concerns\RespondsWithJson;
use App\Http\Controllers\Controller;
use App\Models\AssetDiscovery;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\AuditLogService;
use App\Services\TechnologyFingerprintEngine;
use App\Services\TechnologyGraphExporter;
use App\Services\WorkspaceContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class TechnologyFingerprintController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private readonly WorkspaceContext $workspaceContext,
        private readonly TechnologyFingerprintEngine $fingerprintEngine,
        private readonly TechnologyGraphExporter $graphExporter,
        private readonly AuditLogService $auditLogService,
    ) {
    }

    public function store(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);
        $latestDiscovery = AssetDiscovery::query()->where('website_id', $website->id)->latest('completed_at')->first();
        $result = $this->fingerprintEngine->run($website, $latestDiscovery);

        $this->auditLogService->record(
            'technology_fingerprint.completed',
            $request->user(),
            $workspace->id,
            'website',
            $website->id,
            $request->ip(),
            [
                'asset_discovery_id' => $latestDiscovery?->id,
                'technologies_detected' => count($result['technologies'] ?? []),
                'coverage_percentage' => data_get($result, 'coverage.percentage'),
            ],
        );

        return $this->ok($result, 202);
    }

    public function index(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->fingerprintEngine->summary($website));
    }

    public function coverage(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->fingerprintEngine->coverage($website));
    }

    public function relationships(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->fingerprintEngine->relationships($website));
    }

    public function conflicts(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->fingerprintEngine->conflicts($website));
    }

    public function graph(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->graphExporter->export($website));
    }

    private function findWebsite(int $websiteId, Workspace $workspace): Website
    {
        return Website::query()
            ->where('workspace_id', $workspace->id)
            ->whereKey($websiteId)
            ->firstOrFail();
    }
}
