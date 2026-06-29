# Phase 05 - Scan Orchestrator

## Goal

Gercek scanner motorlari calismadan once queue, worker contract, safety gate, retry, cancellation, timeline/log ve mock executor altyapisini kur.

## Signals

- Ready/generated scan plan items.
- Verified website ownership.
- Workspace quota and concurrent limits.
- Worker capability registry and heartbeat.
- Queue priority and execution budget.

## Acceptance

- Scan plan items `ScanJob` kayitlarina donusur.
- `ExecuteScanJob` yalnizca `MockExecutorService` calistirir.
- Job lifecycle timeline/log olarak saklanir.
- Worker metrics dashboard icin hazirdir.
- Nuclei/ZAP/WPScan/testssl/httpx/katana/subfinder/ffuf/nmap calismaz.
