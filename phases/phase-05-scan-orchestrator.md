# Phase 05 - Scan Orchestrator

## Goal

Scan plan item'larini guvenli queue job'lara donusturen orchestration, worker registry, lock, retry, timeline/log, progress ve mock artifact altyapisini kur.

## Deliverables

- `ScanOrchestratorService`, `ExecuteScanJob`, `MockExecutorService`.
- Worker capability registry ve heartbeat.
- Redis distributed lock.
- Queue priority: `scan-high`, `scan-normal`, `scan-low`, `maintenance`, `ai`, `notification`.
- Per-job execution budget: `max_requests`, `max_runtime`, `max_memory`.
- Per-job timeout, retry config ve scanner override.
- Cooperative cancellation token.
- `ScanJobTimeline` ve `ScanJobLog`.
- Future `ScanSchedule` modeli.
- `ScannerInterface` future adapter sozlesmesi.
- Progress/status updates and mock raw artifact storage.

## Acceptance

- Failed optional job full scan'i gereksiz yere durdurmaz.
- Critical pipeline failure status'a yazilir.
- Audit log her scan lifecycle event'ini gorur.
- Phase 05 hicbir gercek scanner motoru calistirmaz.
- Mock executor queued -> starting -> running -> completed lifecycle ve progress uretir.
- Worker metrics dashboard summary icin hazirdir.
