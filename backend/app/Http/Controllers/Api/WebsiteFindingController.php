<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Concerns\RespondsWithJson;
use App\Http\Controllers\Controller;
use App\Models\Finding;
use App\Models\Website;
use App\Models\Workspace;
use App\Services\FindingStatusTransitionService;
use App\Services\WorkspaceContext;
use App\Support\FindingStatuses;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Validation\Rule;

class WebsiteFindingController extends Controller
{
    use RespondsWithJson;

    public function __construct(
        private readonly WorkspaceContext $workspaceContext,
        private readonly FindingStatusTransitionService $findingStatusTransitionService,
    ) {
    }

    public function index(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);
        $perPage = max(1, min(100, (int) $request->integer('per_page', 25)));

        $query = Finding::query()
            ->where('workspace_id', $workspace->id)
            ->where('website_id', $website->id)
            ->with(['sources', 'taxonomy', 'canonicalFinding'])
            ->when($request->filled('severity'), fn ($query) => $query->where('severity', $request->string('severity')->toString()))
            ->when($request->filled('priority'), fn ($query) => $query->where('priority', $request->string('priority')->toString()))
            ->when($request->filled('status'), fn ($query) => $query->where('status', $request->string('status')->toString()))
            ->when($request->filled('scanner_key'), function ($query) use ($request): void {
                $scannerKey = $request->string('scanner_key')->toString();
                $query->where(function ($query) use ($scannerKey): void {
                    $query
                        ->where('scanner_key', $scannerKey)
                        ->orWhereHas('sources', fn ($sourceQuery) => $sourceQuery->where('scanner_key', $scannerKey));
                });
            })
            ->when($request->filled('cve'), function ($query) use ($request): void {
                $cve = $request->string('cve')->toString();
                $query->where(function ($query) use ($cve): void {
                    $query
                        ->where('cve', $cve)
                        ->orWhere('cve_json', 'like', '%'.$cve.'%');
                });
            })
            ->when($request->filled('search'), function ($query) use ($request): void {
                $search = '%'.$request->string('search')->toString().'%';
                $query->where(function ($query) use ($search): void {
                    $query
                        ->where('title', 'like', $search)
                        ->orWhere('normalized_title', 'like', $search)
                        ->orWhere('affected_url', 'like', $search)
                        ->orWhere('affected_component', 'like', $search)
                        ->orWhere('cve', 'like', $search)
                        ->orWhere('cwe', 'like', $search);
                });
            })
            ->orderByDesc('risk_score')
            ->orderByDesc('last_seen_at');

        $page = $query->paginate($perPage);

        return $this->ok(
            collect($page->items())->map(fn (Finding $finding): array => $this->findingData($finding))->values()->all(),
            meta: [
                'current_page' => $page->currentPage(),
                'per_page' => $page->perPage(),
                'total' => $page->total(),
                'last_page' => $page->lastPage(),
            ],
        );
    }

    public function show(Request $request, int $website, int $findingId): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);
        $finding = $this->findFinding($workspace, $website, $findingId)
            ->load(['sources', 'taxonomy', 'canonicalFinding', 'evidences', 'events', 'riskScoreHistories', 'confidenceHistories', 'relatedFinding']);

        return $this->ok($this->findingData($finding, detail: true));
    }

    public function status(Request $request, int $website, int $findingId): JsonResponse
    {
        $payload = $request->validate([
            'status' => ['required', 'string', Rule::in(FindingStatuses::all())],
            'reason' => ['nullable', 'string', 'max:4000'],
            'create_rule' => ['sometimes', 'boolean'],
            'expires_at' => ['nullable', 'date'],
        ]);
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);
        $finding = $this->findFinding($workspace, $website, $findingId);
        $expiresAt = isset($payload['expires_at']) ? Carbon::parse($payload['expires_at']) : null;

        $finding = $this->findingStatusTransitionService->transition(
            $finding,
            (string) $payload['status'],
            $request->user(),
            $payload['reason'] ?? null,
            ['source' => 'api'],
            (bool) ($payload['create_rule'] ?? false),
            $expiresAt,
        )->load(['sources', 'taxonomy', 'canonicalFinding', 'evidences', 'events']);

        return $this->ok($this->findingData($finding, detail: true));
    }

    public function summary(Request $request, int $website): JsonResponse
    {
        $workspace = $this->workspaceContext->resolve($request->user(), $request);
        $website = $this->findWebsite($website, $workspace);
        $base = Finding::query()
            ->where('workspace_id', $workspace->id)
            ->where('website_id', $website->id);

        return $this->ok([
            'total' => (clone $base)->count(),
            'open' => (clone $base)->whereIn('status', FindingStatuses::active())->count(),
            'average_risk_score' => round((float) ((clone $base)->avg('risk_score') ?? 0), 1),
            'severity' => $this->distribution(clone $base, 'severity'),
            'priority' => $this->distribution(clone $base, 'priority'),
            'status' => $this->distribution(clone $base, 'status'),
            'scanner_sources' => (clone $base)
                ->with('sources')
                ->get()
                ->flatMap(fn (Finding $finding) => $finding->sources->pluck('scanner_key')->push($finding->scanner_key))
                ->filter()
                ->countBy()
                ->all(),
        ]);
    }

    private function findWebsite(int $websiteId, Workspace $workspace): Website
    {
        return Website::query()
            ->where('workspace_id', $workspace->id)
            ->whereKey($websiteId)
            ->firstOrFail();
    }

    private function findFinding(Workspace $workspace, Website $website, int $findingId): Finding
    {
        return Finding::query()
            ->where('workspace_id', $workspace->id)
            ->where('website_id', $website->id)
            ->whereKey($findingId)
            ->firstOrFail();
    }

    /**
     * @return array<string, int>
     */
    private function distribution($query, string $column): array
    {
        return $query
            ->selectRaw($column.', count(*) as total')
            ->groupBy($column)
            ->pluck('total', $column)
            ->map(fn ($value): int => (int) $value)
            ->all();
    }

    /**
     * @return array<string, mixed>
     */
    private function findingData(Finding $finding, bool $detail = false): array
    {
        $data = [
            'id' => $finding->id,
            'workspace_id' => $finding->workspace_id,
            'website_id' => $finding->website_id,
            'scan_id' => $finding->scan_id,
            'title' => $finding->title,
            'normalized_title' => $finding->normalized_title,
            'severity' => $finding->severity,
            'priority' => $finding->priority,
            'status' => $finding->status,
            'risk_score' => $finding->risk_score,
            'confidence_score' => $finding->confidence_score,
            'false_positive_risk' => $finding->false_positive_risk,
            'correlation_score' => $finding->correlation_score,
            'correlation_key' => $finding->correlation_key,
            'scanner_key' => $finding->scanner_key,
            'source_tool' => $finding->source_tool,
            'template_id' => $finding->template_id,
            'affected_url' => $finding->affected_url,
            'affected_component' => $finding->affected_component,
            'affected_parameter' => $finding->affected_parameter,
            'asset_type' => $finding->asset_type,
            'asset_identifier' => $finding->asset_identifier,
            'cve' => $finding->cve_json ?? array_values(array_filter([$finding->cve])),
            'cwe' => $finding->cwe_json ?? array_values(array_filter([$finding->cwe])),
            'cvss_score' => $finding->cvss_score ?? $finding->cvss,
            'owasp_category' => $finding->owasp_category,
            'occurrence_count' => $finding->occurrence_count,
            'first_seen_at' => $finding->first_seen_at?->toISOString(),
            'last_seen_at' => $finding->last_seen_at?->toISOString(),
            'resolved_at' => $finding->resolved_at?->toISOString(),
            'reopened_at' => $finding->reopened_at?->toISOString(),
            'sla_due_at' => $finding->sla_due_at?->toISOString(),
            'analysis_required' => $finding->analysis_required,
            'analysis_version' => $finding->analysis_version,
            'analysis_status' => $finding->analysis_status,
            'taxonomy' => $finding->taxonomy ? [
                'category' => $finding->taxonomy->category,
                'subcategory' => $finding->taxonomy->subcategory,
                'owasp_category' => $finding->taxonomy->owasp_category,
                'asvs_control' => $finding->taxonomy->asvs_control,
                'cwe' => $finding->taxonomy->cwe,
                'capec' => $finding->taxonomy->capec,
            ] : null,
            'canonical' => $finding->canonicalFinding ? [
                'id' => $finding->canonicalFinding->id,
                'normalized_key' => $finding->canonicalFinding->normalized_key,
                'default_title' => $finding->canonicalFinding->default_title,
            ] : null,
            'sources' => $finding->sources->map(fn ($source): array => [
                'scanner_key' => $source->scanner_key,
                'scan_job_id' => $source->scan_job_id,
                'raw_artifact_id' => $source->raw_artifact_id,
                'template_id' => $source->template_id,
                'source_severity' => $source->source_severity,
                'source_confidence' => $source->source_confidence,
                'observed_at' => $source->observed_at?->toISOString(),
            ])->values()->all(),
        ];

        if (! $detail) {
            return $data;
        }

        return [
            ...$data,
            'description' => $finding->description,
            'normalized_description' => $finding->normalized_description,
            'evidence' => $finding->evidence_json,
            'evidence_text' => $finding->evidence,
            'remediation' => $finding->remediation,
            'references' => $finding->references ?? [],
            'ai_summary' => $finding->ai_summary,
            'recommended_action' => data_get($finding->metadata, 'recommended_action'),
            'related_finding' => $finding->relatedFinding ? [
                'id' => $finding->relatedFinding->id,
                'title' => $finding->relatedFinding->title,
                'risk_score' => $finding->relatedFinding->risk_score,
            ] : null,
            'evidences' => $finding->evidences->map(fn ($evidence): array => [
                'id' => $evidence->id,
                'type' => $evidence->type,
                'mime' => $evidence->mime,
                'sha256' => $evidence->sha256,
                'artifact_id' => $evidence->artifact_id,
                'thumbnail' => $evidence->thumbnail,
                'preview' => $evidence->preview,
            ])->values()->all(),
            'events' => $finding->events->sortByDesc('changed_at')->map(fn ($event): array => [
                'old_status' => $event->old_status,
                'new_status' => $event->new_status,
                'reason' => $event->reason,
                'changed_by_user_id' => $event->changed_by_user_id,
                'changed_at' => $event->changed_at?->toISOString(),
            ])->values()->all(),
            'risk_history' => $finding->riskScoreHistories->sortByDesc('calculated_at')->map(fn ($history): array => [
                'old_score' => $history->old_score,
                'new_score' => $history->new_score,
                'reason' => $history->reason,
                'calculated_at' => $history->calculated_at?->toISOString(),
            ])->values()->all(),
            'confidence_history' => $finding->confidenceHistories->sortByDesc('calculated_at')->map(fn ($history): array => [
                'confidence' => $history->confidence,
                'reason' => $history->reason,
                'scanner' => $history->scanner,
                'calculated_at' => $history->calculated_at?->toISOString(),
            ])->values()->all(),
        ];
    }
}
