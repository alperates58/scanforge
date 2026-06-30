<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\AssetDiscovery;
use App\Models\Finding;
use App\Models\Scan;
use App\Models\ScannerMetric;
use App\Models\ScannerVersion;
use App\Models\Website;
use App\Services\ScanMetricsService;
use App\Services\WorkspaceContext;
use App\Support\FindingStatuses;
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
        $activeStatuses = FindingStatuses::active();
        $criticalFindings = $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('severity', 'critical')->whereIn('status', $activeStatuses)->count());
        $highFindings = $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('severity', 'high')->whereIn('status', $activeStatuses)->count());
        $averageFindingRisk = $metric(fn () => round((float) (Finding::query()->whereIn('website_id', $websiteIds())->whereIn('status', $activeStatuses)->avg('risk_score') ?? 0), 1));
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
                'open_findings' => $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->whereIn('status', $activeStatuses)->count()),
                'passive_findings' => $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('source_tool', 'scanforge-passive-discovery')->whereIn('status', $activeStatuses)->count()),
                'resolved_findings' => $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('status', FindingStatuses::RESOLVED)->count()),
                'false_positive_findings' => $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('status', FindingStatuses::FALSE_POSITIVE)->count()),
                'discoveries' => $metric(fn () => AssetDiscovery::query()->whereIn('website_id', $websiteIds())->count()),
            ],
            'risk' => [
                'average_score' => $averageFindingRisk,
                'average_finding_risk_score' => $averageFindingRisk,
                'average_scan_score' => $metric(fn () => round((float) (Scan::query()->whereIn('website_id', $websiteIds())->whereNotNull('score')->avg('score') ?? 0), 1)),
                'critical_findings' => $criticalFindings,
                'high_findings' => $highFindings,
                'resolved_findings' => $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('status', FindingStatuses::RESOLVED)->count()),
                'false_positive_findings' => $metric(fn () => Finding::query()->whereIn('website_id', $websiteIds())->where('status', FindingStatuses::FALSE_POSITIVE)->count()),
                'top_risky_websites' => $this->topRiskyWebsites($workspace->id, $metric),
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
            'scanner_versions' => $this->scannerVersions($metric),
            'scanner_metrics' => $this->scannerMetrics($metric),
        ]);
    }

    /**
     * @param callable(callable): (int|float) $metric
     * @return list<array<string, mixed>>
     */
    private function scannerVersions(callable $metric): array
    {
        $metric(fn () => ScannerVersion::query()->count());

        try {
            return ScannerVersion::query()
                ->orderBy('scanner_key')
                ->get()
                ->map(fn (ScannerVersion $version): array => [
                    'scanner_key' => $version->scanner_key,
                    'binary_version' => $version->binary_version,
                    'templates_version' => $version->templates_version,
                    'last_checked_at' => $version->last_checked_at?->toISOString(),
                    'status' => $version->status,
                ])
                ->values()
                ->all();
        } catch (QueryException) {
            return [];
        }
    }

    /**
     * @param callable(callable): (int|float) $metric
     * @return list<array<string, mixed>>
     */
    private function scannerMetrics(callable $metric): array
    {
        $metric(fn () => ScannerMetric::query()->count());

        try {
            return ScannerMetric::query()
                ->orderBy('scanner_key')
                ->get()
                ->map(fn (ScannerMetric $scannerMetric): array => [
                    'scanner_key' => $scannerMetric->scanner_key,
                    'runs' => $scannerMetric->runs,
                    'success' => $scannerMetric->success,
                    'failed' => $scannerMetric->failed,
                    'timeout' => $scannerMetric->timeout,
                    'avg_runtime' => $scannerMetric->avg_runtime,
                    'avg_findings' => $scannerMetric->avg_findings,
                    'last_run_at' => $scannerMetric->last_run_at?->toISOString(),
                ])
                ->values()
                ->all();
        } catch (QueryException) {
            return [];
        }
    }

    /**
     * @param callable(callable): (int|float) $metric
     * @return list<array<string, mixed>>
     */
    private function topRiskyWebsites(int $workspaceId, callable $metric): array
    {
        $metric(fn () => Website::query()->where('workspace_id', $workspaceId)->count());

        try {
            return Website::query()
                ->where('workspace_id', $workspaceId)
                ->orderByDesc('risk_score')
                ->limit(5)
                ->get()
                ->map(fn (Website $website): array => [
                    'id' => $website->id,
                    'host' => $website->host,
                    'risk_score' => $website->risk_score,
                    'critical_count' => $website->critical_count,
                    'high_count' => $website->high_count,
                    'trend' => $website->risk_trend,
                ])
                ->values()
                ->all();
        } catch (QueryException) {
            return [];
        }
    }
}
