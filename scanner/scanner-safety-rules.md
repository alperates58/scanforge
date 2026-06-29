# Scanner Safety Rules

1. Active scans only for verified domains.
2. No brute force.
3. No destructive payloads.
4. No exploit execution that changes server state.
5. No file upload exploit tests in MVP.
6. Rate limit all requests.
7. Max request budget per scan type.
8. Per-job timeout.
9. Record all scanner commands.
10. Aggressive mode requires explicit admin flag, not in MVP.

## Scan Budgets
Passive: max 100 requests
Standard: max 2,000 requests
Deep: max 10,000 requests
Authenticated: configurable but bounded

## Nuclei
Use tags and severity filters. Exclude destructive, intrusive, dos, fuzz-heavy templates unless explicitly reviewed.
