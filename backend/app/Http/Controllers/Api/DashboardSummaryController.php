<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\AssetDiscovery;
use App\Models\Finding;
use App\Models\Scan;
use App\Models\Website;
use App\Services\ScanMetricsService;
use App\Services\WorkspaceContext;
use Illuminate\Database\QueryException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

class DashboardSummaryController extends Controller
{
    public function __invoke(Request $request, WorkspaceContext $workspaceContext, ScanMetricsService $scanMetricsService): JsonResponse
    {
        $workspace = $workspaceContext->resolve($request->user(), $request);
        $schemaReady = true;

        $metric = function (callable $callback) use (&$schemaReady): int|float {
            try {
                return $callback();
            } catch (QueryException) {
                $schemaReady = false;

                return 0;
            }
        };

        $websiteIds = fn () => Website::query()->where('workspace_id', $workspace->id)->select('id');
        $criticalFindings = $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('severity', 'critical')->where('status', 'open')->count());
        $highFindings = $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('severity', 'high')->where('status', 'open')->count());
        $latestScanStatus = null;

        try {
            $latestScanStatus = Scan::query()->whereIn('website_id', $websiteIds())->latest('created_at')->value('status');
        } catch (QueryException) {
            $schemaReady = false;
        }

        $latestDiscoveryAt = null;
        $latestDiscoveryStatus = null;

        try {
            $latestDiscovery = AssetDiscovery::query()->whereIn('website_id', $websiteIds())->latest('created_at')->first();
            $latestDiscoveryAt = $latestDiscovery?->completed_at?->toISOString();
            $latestDiscoveryStatus = $latestDiscovery?->status;
        } catch (QueryException) {
            $schemaReady = false;
        }

        return response()->json([
            'schema_ready' => $schemaReady,
            'totals' => [
                'websites' => $metric(fn () => Website::query()->where('workspace_id', $workspace->id)->count()),
                'verified_websites' => $metric(fn () => Website::query()->where('workspace_id', $workspace->id)->where('verification_status', 'verified')->count()),
                'scans' => $metric(fn () => Scan::query()->whereIn('website_id', $websiteIds())->count()),
                'open_findings' => $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('status', 'open')->count()),
                'passive_findings' => $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('source_tool', 'scanforge-passive-discovery')->where('status', 'open')->count()),
                'discoveries' => $metric(fn () => AssetDiscovery::query()->whereIn('website_id', $websiteIds())->count()),
            ],
            'risk' => [
                'average_score' => $metric(fn () => round((float) (Scan::query()->whereIn('website_id', $websiteIds())->whereNotNull('score')->avg('score') ?? 0), 1)),
                'critical_findings' => $criticalFindings,
                'high_findings' => $highFindings,
            ],
            'activity' => [
                'scans_this_week' => $metric(fn () => Scan::query()->whereIn('website_id', $websiteIds())->where('created_at', '>=', Carbon::now()->subWeek())->count()),
                'latest_scan_status' => $latestScanStatus,
                'last_discovery_at' => $latestDiscoveryAt,
                'latest_discovery_status' => $latestDiscoveryStatus,
            ],
            'safety' => [
                'unverified_domain_scans_allowed' => (bool) config('scanforge.scanner.allow_unverified_domains'),
                'default_safe_mode' => (bool) config('scanforge.scanner.safe_mode'),
                'workspace_concurrent_scan_limit' => (int) $workspace->concurrent_scan_limit,
            ],
            'workspace' => [
                'id' => $workspace->id,
                'plan_name' => $workspace->plan_name,
                'monthly_scan_limit' => $workspace->monthly_scan_limit,
                'scans_used_this_month' => $workspace->scans_used_this_month,
            ],
            'worker_metrics' => $scanMetricsService->workspaceMetrics($workspace->id),
        ]);
    }
}
