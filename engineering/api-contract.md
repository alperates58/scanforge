# API Contract

Phase 06 API token-first calisir. Health public kalir; urun endpoint'leri `Authorization: Bearer <token>` bekler. Protected endpoint'lerde opsiyonel `X-Workspace-Id` header'i kullanilabilir.

## Response Shape

- Success: `{ "data": ... }` veya `{ "data": ..., "meta": ... }`
- Validation/auth errors: `{ "message": "...", "errors": { "field": ["..."] } }`
- `GET /api/health` dependency probe oldugu icin Phase 01 raw health formatini korur.

## Auth

- `POST /api/auth/register`
  - Body: `{ "name": "...", "email": "...", "password": "min-8" }`
  - Creates user, personal workspace and owner membership.
  - Returns user, workspace and Sanctum token.
- `POST /api/auth/login`
  - Body: `{ "email": "...", "password": "..." }`
  - Returns user, first workspace and token.
- `POST /api/auth/logout`
- `GET /api/me`

## Websites

- `GET /api/websites`
- `POST /api/websites`
  - Body: `{ "url": "https://example.com", "environment": "production|staging|development|other", "importance": "low|normal|high|critical", "notes": null, "tags": ["production"] }`
  - URL normalizer only allows http/https and rejects localhost, private/reserved IPs, metadata IPs, internal suffixes and credential-bearing URLs.
  - Returns website plus verification instructions.
- `GET /api/websites/{id}`
- `DELETE /api/websites/{id}`

## Domain Verification

- `GET /api/websites/{id}/verification`
  - Returns token and methods: DNS TXT, HTML file, meta tag.
  - Token is not stored plaintext. DB stores `verification_token_hash`.
- `POST /api/websites/{id}/verification/check`
  - Checks DNS TXT, `/.well-known/scanforge-verify.txt`, and root meta tag.
  - HTTP checks use short timeout and same-host redirects only.
  - Success sets `ownership_verified_at`, `verified_at`, `verification_method`, `verification_status=verified`.

## Scan Orchestration

- `POST /api/websites/{id}/scans`
  - Body: `{ "scan_type": "passive|standard|deep|authenticated", "safety_mode": "safe|standard|deep|authenticated", "scan_plan_id": 123, "consent_accepted": true, "credential_id": null, "options": {} }`
  - `scan_plan_id` is optional; latest ready/generated plan is used when omitted.
  - Requires workspace ownership, verified website, public host, consent, ready scan plan, quota, concurrent capacity and safety gate approval.
  - Creates `Scan(status=queued)` and one `ScanJob(status=queued)` per scan plan item.
  - Dispatches `ExecuteScanJob` to priority queues after worker capability check.
  - Scanner execution is resolved through `ScannerRegistry`; Phase 06 enables the Nuclei adapter only when `NUCLEI_ENABLED=true`.
  - Errors: `409 scan_plan_required`, `429 quota_exceeded`, `429 concurrent_scan_limit_exceeded`, `429 scan_lock_active`, `403 safety_gate_rejected`.
- `GET /api/websites/{id}/scans`
  - Returns latest 25 scan summaries.
- `GET /api/websites/{id}/scans/{scanId}`
  - Returns scan summary, jobs, plan info, progress, timings, artifact count and recent finding mini-list.
  - `recent_findings[]`: `title`, `severity`, `scanner_key`, `template_id`, `affected_url`, `matched_at`, `raw_artifact_id`, `has_raw_evidence`.
- `GET /api/websites/{id}/scans/{scanId}/jobs`
  - Returns job contract rows for a scan.
- `POST /api/websites/{id}/scans/{scanId}/cancel`
  - Marks queued/pending/starting/running jobs cancelled and records cooperative cancellation tokens.
- `POST /api/websites/{id}/scans/{scanId}/retry-failed`
  - Requeues failed/timeout jobs whose `attempt_count < max_attempts`.
  - No separate "run nuclei" endpoint exists. Nuclei only runs through orchestrated scan jobs.

## Findings

- `GET /api/websites/{id}/findings`
  - Authenticated and workspace-scoped.
  - Filters: `severity`, `priority`, `status`, `scanner_key`, `cve`, `search`.
  - Default sort: `risk_score desc`, `last_seen_at desc`.
  - Returns normalized finding rows with taxonomy, canonical reference and scanner source badges.
- `GET /api/websites/{id}/findings/{findingId}`
  - Returns detail with evidence attachments, remediation, references, related finding, events, risk history and confidence history.
- `POST /api/websites/{id}/findings/{findingId}/status`
  - Body: `{ "status": "new|confirmed|ignored|resolved|false_positive|reopened", "reason": "...", "create_rule": false, "expires_at": null }`
  - Creates `finding_events` and compatibility `finding_histories`.
  - When `create_rule=true` and status is `ignored` or `false_positive`, creates a `suppression_rules` record for scanner/template/host.
- `GET /api/websites/{id}/findings/summary`
  - Returns severity, priority, status and scanner-source distributions plus average risk.

## Asset Discovery

- `POST /api/websites/{id}/discoveries`
  - Requires authenticated workspace membership and `website.isVerified()`.
  - Runs bounded passive discovery only: DNS lookup, one root HTTP observation with limited same-root redirects, favicon hash, robots/sitemap existence, TLS certificate metadata, optional WHOIS.
  - If DNS resolves to private/reserved/internal IPs, discovery is marked `failed`, HTTP is not requested and a high-severity passive finding is recorded.
  - Response status: `202`.
  - Response data: `AssetDiscovery` envelope with `status`, timeline timestamps, `metrics`, `summary`, `discovery_score`, `analysis_required`.
- `GET /api/websites/{id}/discoveries`
  - Returns latest 25 discovery runs scoped to the current workspace.
- `GET /api/websites/{id}/discoveries/{discoveryId}`
  - Returns one discovery run when it belongs to the requested website and workspace.
- `GET /api/websites/{id}/assets/summary`
  - Returns the latest passive asset profile: DNS counts, IPs, HTTP snapshot, security header matrix, cookie summary, TLS, WHOIS, robots/sitemap, passive findings and technology hints.

### Asset Discovery Response Notes

- `security_headers` is a normalized matrix keyed by `hsts`, `csp`, `x_frame_options`, `x_content_type_options`, `permissions_policy`, `referrer_policy`, `cross_origin_embedder_policy`, `cross_origin_opener_policy`, `cross_origin_resource_policy`.
- `favicon_hash` is a SHA-256 hash of `/favicon.ico` when present.
- Technology hints use `confidence_score` between 30 and 70 in Phase 03. They are planning signals, not vulnerability claims.
- `analysis_required=true` only marks AI readiness. Phase 03 does not call DeepSeek or any other model.

## Technology Fingerprinting

- `POST /api/websites/{id}/fingerprint`
  - Requires authenticated workspace membership and verified ownership.
  - Runs plugin registry + rule evaluator against latest passive observations.
  - Response status: `202`.
  - Returns `technologies`, `coverage`, `relationships`, `conflicts`.
  - Creates immutable `technology_evidences`, version/confidence history, technology graph and coverage metadata.
- `GET /api/websites/{id}/technologies`
  - Returns active fingerprints with evidence samples, coverage, relationships and conflicts.
- `GET /api/websites/{id}/technology-coverage`
  - Returns normalized category coverage: server, language, framework, CMS, CDN, hosting, database, frontend, WAF, analytics.
- `GET /api/websites/{id}/technology-relationships`
  - Returns graph edges such as `cloudflare -> nginx -> php -> laravel`.
- `GET /api/websites/{id}/technology-conflicts`
  - Returns open conflict objects for AI/operator review.
- `GET /api/websites/{id}/technology-graph`
  - Exports website, asset graph, technology nodes, relationships and latest scan plan as AI-ready JSON.

### Fingerprint Response Notes

- `confidence_score` is detection confidence.
- `quality_score` is evidence breadth/quality and is intentionally different from confidence.
- `cpe_candidates` uses object records: `{ confidence, source, cpe, version }`.
- `analysis_required=true` and `analysis_version` are stored per fingerprint for Phase 09 AI processing.
- Phase 04 does not run Nuclei, ZAP, WPScan, testssl, httpx, katana or subfinder.

## Scan Plans

- `POST /api/websites/{id}/scan-plans`
  - Generates a safe scan plan from current active fingerprints and capability resolver output.
  - Response status: `201`.
  - Returns `coverage_prediction`, cost estimates and `items`.
- `GET /api/websites/{id}/scan-plans`
  - Returns latest 20 generated plans.
- `GET /api/websites/{id}/scan-plans/{scanPlanId}`
  - Returns one plan scoped to the website/workspace.

### Scan Plan Response Notes

- `recommendation_score` is 0-100 and combines fingerprint confidence, quality, capability priority and safe-mode status.
- `estimated_runtime_seconds`, `estimated_requests`, `estimated_cpu`, `estimated_memory_mb` are scheduler estimates only.
- A generated plan is not execution approval; scan gates and user consent remain required.

## Dashboard

- `GET /api/dashboard/summary`
  - Authenticated and workspace-scoped.
  - Returns totals, passive findings, discovery totals, latest discovery activity, finding risk counters, resolved/false-positive counts, top risky websites, safety defaults, workspace quota metadata, worker metrics, scanner versions and scanner metrics.
