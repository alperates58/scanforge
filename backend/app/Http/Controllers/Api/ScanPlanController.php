<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Concerns\RespondsWithJson;
use App\Http\Controllers\Controller;
use App\Models\ScanPlan;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\AuditLogService;
use App\Services\ScanPlanService;
use App\Services\WorkspaceContext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ScanPlanController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private readonly WorkspaceContext $workspaceContext,
        private readonly ScanPlanService $scanPlanService,
        private readonly AuditLogService $auditLogService,
    ) {
    }

    public function store(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);
        $plan = $this->scanPlanService->generate($website);

        $this->auditLogService->record(
            'scan_plan.generated',
            $request->user(),
            $workspace->id,
            'scan_plan',
            $plan['id'],
            $request->ip(),
            [
                'website_id' => $website->id,
                'coverage_prediction' => $plan['coverage_prediction'],
                'estimated_requests' => $plan['estimated_requests'],
                'safe_mode' => $plan['safe_mode'],
            ],
        );

        return $this->ok($plan, 201);
    }

    public function index(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);

        return $this->ok($this->scanPlanService->list($website));
    }

    public function show(Request $request, int $website, int $scanPlan): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);
        $plan = ScanPlan::query()
            ->where('website_id', $website->id)
            ->whereKey($scanPlan)
            ->with('items')
            ->firstOrFail();

        return $this->ok($this->scanPlanService->planData($plan));
    }

    private function findWebsite(int $websiteId, Workspace $workspace): Website
    {
        return Website::query()
            ->where('workspace_id', $workspace->id)
            ->whereKey($websiteId)
            ->firstOrFail();
    }
}
