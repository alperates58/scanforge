# Phase 06 - Nuclei Engine Adapter and Safe Template Execution

## Goal

Add Nuclei as the first real scanner engine while preserving ScanForge's verified-target safety boundary.

## Architecture

- Scanner execution resolves through `scanner_key -> ScannerRegistry -> ScannerInterface`.
- Nuclei is a plugin-style adapter in `App\Scanners\Nuclei\NucleiScanner`.
- New scanner engines should require one adapter class and one `config/scanners.php` registry entry.
- `ScannerVersion`, `TemplateManifest`, `ScannerMetric`, `ArtifactManifest`, `FindingHistory`, and `CveReference` are architectural preparation for later phases.

## Safe Execution

- `NUCLEI_ENABLED=false` by default.
- Nuclei runs only for verified websites with consent and a ready scan plan item.
- Private/internal targets remain blocked by `TargetUrlGuard`.
- Template policy allowlist is required. Unknown groups are blocked.
- DoS, fuzzing, brute-force, intrusive, destructive and aggressive exploit tags remain blocked.
- Each job runs in `/tmp/scanforge/{job_uuid}/` with isolated `work`, `tmp`, and `output` directories.
- Nuclei command args are built as arrays through Symfony Process.

## Normalization

Nuclei JSONL is normalized into `findings` with:

- `scanner_key=nuclei`
- `template_id`
- `matched_at`
- `description`
- `remediation`
- `references`
- nullable `cvss`, `cve`, `cwe`
- `evidence_json`
- `confidence_score`
- `false_positive_risk`
- `raw_artifact_id`

Finding dedupe uses `scanner_key + template_id + affected_url + parameter`. Repeated findings update `last_seen_at` and `occurrence_count`.

## Acceptance

- Disabled Nuclei jobs skip safely.
- Unverified or non-public targets are rejected before process execution.
- Safe policy groups run; blocked policy groups do not.
- Raw JSONL creates `RawArtifact` and `ArtifactManifest`.
- Dashboard can show scanner versions and scanner metrics.
- Frontend scan detail shows Nuclei jobs, severity badges, template IDs and raw evidence availability.
