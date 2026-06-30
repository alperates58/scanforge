# Phase 06 - Nuclei Integration

## Goal

Nuclei safe template setlerini verified domainlerde calistir.

## Deliverables

- Nuclei adapter.
- Template allow/deny policy.
- JSON output parser.
- Finding normalization.
- Scanner adapter registry.
- Scanner version and metrics tracking.
- Template and artifact manifests.
- Finding dedupe and finding history.
- Execution sandbox per ScanJob.

## Acceptance

- Destructive, intrusive, dos and brute-force templates disabled.
- Nuclei findings schema ile uyumlu normalize edilir.
- Nuclei sadece orchestrator ve registry uzerinden calisir.
- `NUCLEI_ENABLED=false` defaulttur.
