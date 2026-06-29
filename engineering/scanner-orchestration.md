# Scanner Orchestration

Scanner orchestration, backend tarafindan dogrulanmis scan islerini queue uzerinden worker'a aktaran sozlesmedir. Worker hedef secmez; sadece kendisine verilen verified job contract'ini isler. Phase 05 queue, worker registry, lock, retry, timeline, log ve mock executor altyapisini kurar; gercek scanner motoru calistirmaz.

## Job Contract

- `scan_id`
- `website_id`
- `target_url`
- `normalized_host`
- `scan_type`
- `safe_mode`
- `request_budget`
- `rate_limit_per_second`
- `timeout_seconds`
- `technology_fingerprints`
- `scan_plan_item_id`
- `scanner_key`
- `scan_module`
- `template_group`
- `queue_name`
- `max_requests`
- `max_runtime`
- `max_memory`
- `cancellation_token`

## Pipeline

1. Validate workspace membership, website ownership and verified status.
2. Enforce consent, scan plan readiness, quota, concurrent limits and public-host rules.
3. Acquire Redis lock `scanforge:scan:{website_id}` before creating execution jobs.
4. Convert scan plan items into `ScanJob` rows with queue priority and execution budget.
5. Dispatch `ExecuteScanJob` jobs to `scan-high`, `scan-normal` or `scan-low`.
6. Mock executor runs `queued -> starting -> running -> completed` lifecycle and writes timelines/logs/artifacts.
7. Store raw artifact before future normalization.
8. Publish lifecycle and worker events for AI, scheduler and notification phases.

## Phase 05 Worker Contract

- `scan_workers` records worker capability and heartbeat: `worker_id`, hostname, version, supported scanners, status, current/max jobs and metadata.
- `WorkerRegistered` and `WorkerHeartbeat` events are published for future scheduler and orphan-job detection.
- Worker assignment is stored on `scan_jobs.worker_id`; Phase 05 uses `SCANFORGE_WORKER_ID` or hostname fallback.
- `ScanJobTimeline` stores every state transition for AI and operations.
- `ScanJobLog` stores timestamped structured logs with secret redaction.
- Retry policy is config driven with scanner-specific overrides.
- `ScannerInterface` defines `execute`, `cancel`, `validate` and `supports` for Phase 06 adapters.

## Queue Priority

- `priority >= 80`: `scan-high`
- `priority <= 30`: `scan-low`
- otherwise: `scan-normal`
- Reserved queues: `maintenance`, `ai`, `notification`.

## Execution Safety

- Phase 05 only runs `MockExecutorService`.
- Execution budgets are recorded per job: `max_requests`, `max_runtime`, `max_memory`.
- Cancellation is cooperative through `cancel_requested_at` and `cancellation_token`.
- Redis lock timeout is configurable with `SCANFORGE_SCAN_LOCK_TTL_SECONDS`.

## Still Out of Scope

Nuclei, OWASP ZAP, WPScan, testssl.sh, httpx, katana, subfinder, ffuf, nmap, brute force and intrusive crawlers remain disabled in Phase 05.
