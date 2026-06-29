<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Concerns\RespondsWithJson;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\StartScanRequest;
use App\Exceptions\ScanOrchestrationException;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\ScanOrchestratorService;
use App\Services\WorkspaceContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class WebsiteScanController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private readonly WorkspaceContext $workspaceContext,
        private readonly ScanOrchestratorService $scanOrchestratorService,
    ) {
    }

    public function store(StartScanRequest $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        try {
            return $this->ok(
                $this->scanOrchestratorService->start($workspace, $website, $request->user(), $request->validated(), $request->ip()),
                202,
            );
        } catch (ScanOrchestrationException $exception) {
            return $this->scanError($exception);
        }
    }

    public function index(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->scanOrchestratorService->list($workspace, $website));
    }

    public function show(Request $request, int $website, int $scan): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->scanOrchestratorService->detail($workspace, $website, $scan));
    }

    public function cancel(Request $request, int $website, int $scan): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->scanOrchestratorService->cancel($workspace, $website, $request->user(), $scan, $request->ip()));
    }

    public function retryFailed(Request $request, int $website, int $scan): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        try {
            return $this->ok($this->scanOrchestratorService->retryFailed($workspace, $website, $request->user(), $scan, $request->ip()));
        } catch (ScanOrchestrationException $exception) {
            return $this->scanError($exception);
        }
    }

    public function jobs(Request $request, int $website, int $scan): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->scanOrchestratorService->jobs($workspace, $website, $scan));
    }

    private function findWebsite(int $websiteId, Workspace $workspace): Website
    {
        return Website::query()
            ->where('workspace_id', $workspace->id)
            ->whereKey($websiteId)
            ->firstOrFail();
    }

    private function scanError(ScanOrchestrationException $exception): JsonResponse
    {
        return response()->json([
            'message' => $exception->getMessage(),
            'error_code' => $exception->errorCode,
            'errors' => [
                'scan' => $exception->reasons,
            ],
        ], $exception->statusCode);
    }
}
