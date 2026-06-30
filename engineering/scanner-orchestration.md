# Scanner Orchestration

Scanner orchestration, backend tarafindan dogrulanmis scan islerini queue uzerinden worker'a aktaran sozlesmedir. Worker hedef secmez; sadece kendisine verilen verified job contract'ini isler. Phase 06 ile scanner execution `scanner_key -> ScannerRegistry -> ScannerInterface` akisi uzerinden cozulur.

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
- `job_uuid`

## Pipeline

1. Validate workspace membership, website ownership and verified status.
2. Enforce consent, scan plan readiness, quota, concurrent limits and public-host rules.
3. Acquire Redis lock `scanforge:scan:{website_id}` before creating execution jobs.
4. Convert scan plan items into `ScanJob` rows with queue priority and execution budget.
5. Dispatch oncesi worker capability `supports(scanner_key)` kontrol edilir.
6. Dispatch `ExecuteScanJob` jobs to `scan-high`, `scan-normal` or `scan-low`.
7. `ExecuteScanJob` `ScannerExecutorService` kullanir; executor adapter'i `ScannerRegistry` uzerinden cozer.
8. Adapter `queued -> starting -> running -> completed|failed|timeout|cancelled|skipped` lifecycle yazar.
9. Raw artifact, artifact manifest, scanner metrics ve Phase 07 Finding Engine kayitlari uretilir.
10. Publish lifecycle and worker events for AI, scheduler and notification phases.

## Phase 06 Adapter Registry

- `ScannerRegistry` tek public cozumleme noktasidir.
- `ScannerResolver` registry istegini scanner key ve module ile dogrular.
- `ScannerFactory` config kaydindan adapter class olusturur.
- Yeni scanner eklemek icin bir `ScannerInterface` adapter'i ve `config/scanners.php` kaydi yeterlidir.
- Phase 06 kayitlari: `nuclei` ve mock fallback.

## Phase 06 Nuclei Execution

- Nuclei sadece verified website, consent, ready scan plan item ve public target host ile calisir.
- `NUCLEI_ENABLED=false` defaulttur; disabled durumda job skipped olur.
- Template policy DB/config allowlist uzerinden okunur. Unknown group blocked defaulttur.
- Nuclei command Symfony Process ile array arguman olarak kurulur; shell string kullanilmaz.
- Her job icin `/tmp/scanforge/{job_uuid}/work`, `tmp`, `output` sandbox dizinleri olusturulur ve run bitince temizlenir.
- Raw JSONL DB `RawArtifact.content` icinde saklanir; `ArtifactManifest` checksum, size, mime ve retention policy tutar.
- Findings `FindingNormalizationService -> FindingCorrelationService -> FindingRiskEngine` akisi ile normalize edilir. Dedupe artik scanner bagimsiz correlation rules ile calisir; `finding_sources` scanner/job/artifact izini saklar.

## Phase 07 Finding Engine

- Scanner adapter'lari finding modelini dogrudan yazmaz; raw result'i normalization service'e verir.
- Passive discovery bulgulari da ayni engine'den gecer.
- Correlation score 0-100 araligindadir ve farkli scanner/source sinyali geldikce artabilir.
- Risk score history, confidence history, evidence attachment ve source records AI Analyst icin canonical veri uretir.
- Suppression rules status transition API uzerinden uretilir ve sonraki ayni kapsamli bulgulara uygulanir.

## Worker Contract

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

- Phase 07 Nuclei disinda gercek scanner calistirmaz.
- Execution budgets are recorded per job: `max_requests`, `max_runtime`, `max_memory`.
- Cancellation is cooperative through `cancel_requested_at` and `cancellation_token`.
- Redis lock timeout is configurable with `SCANFORGE_SCAN_LOCK_TTL_SECONDS`.
- Nuclei `-restrict-local-network-access`, `-no-interactsh`, `-omit-raw`, blocked tags ve rate limit ile calisir.

## Still Out of Scope

OWASP ZAP, WPScan, testssl.sh, httpx, katana, subfinder, ffuf, nmap, brute force, fuzzing, DoS and intrusive crawlers remain disabled in Phase 06.
