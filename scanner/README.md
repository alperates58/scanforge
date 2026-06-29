# ScanForge Scanner Worker

Phase 01 uses a mock worker only. It does not run Nuclei, ZAP, WPScan, httpx,
testssl.sh, crawlers, brute force tools, or exploit checks.

## Contract

The mock worker writes `/data/mock-scan-result.json` using the normalized
finding shape documented in `normalization-contract.md` and `schemas/`.

## Safety Defaults

- Verified-domain enforcement is owned by the backend scan safety gate.
- `ALLOW_UNVERIFIED_DOMAINS=false` by default.
- `SCAN_SAFE_MODE=true` by default.
- `external_tools_executed` remains an empty list in Phase 01.

Future phases add tool adapters behind the same job contract and safety profile.
