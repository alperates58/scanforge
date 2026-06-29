# Job Orchestration

## Standard Scan Order
1. discovery_scan
2. technology_fingerprint
3. ssl_scan
4. header_scan
5. cookie_scan
6. dns_scan
7. nuclei_safe_scan
8. zap_baseline_scan
9. cms_framework_scan
10. normalize_and_dedupe
11. scoring
12. ai_analysis

## Rules
- Jobs should be idempotent.
- Every job writes raw artifact before normalization.
- Every external command has timeout.
- Every scanner uses per-domain rate limit.
- Failed optional scanner should not kill full scan unless critical pipeline stage.
