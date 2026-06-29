# Scanner Safety Rules

Scanner katmani guvenli, sinirli ve tekrar edilebilir calismalidir. Phase 03'e kadar gercek tool calismaz; ancak asagidaki kurallar mock worker contract'ina ve discovery servislerine dahil edilir.

## Execution Rules

- Verified domain olmadan active scanner job calismaz.
- Her job idempotent olmali ve ayni input icin tekrar calistirilabilir olmalidir.
- Her tool adapter timeout, retry policy ve request budget alir.
- Rate limit per workspace ve per target uygulanir.
- Tool stdout/stderr raw artifact olarak saklanabilir, ancak secret redaction uygulanir.
- Destructive, intrusive, dos, brute-force ve fuzz-heavy template'ler varsayilan disidir.
- Asset discovery scanner worker'a target vermez; verified website icin backend-local pasif metadata toplar.

## Scan Budgets

- Passive: max 100 request.
- Standard: max 2,000 request.
- Deep: max 10,000 request, explicit plan gerektirir.
- Authenticated: bounded ve test account/cookie kullanimi gerektirir.

## Mock Worker Contract

Phase 01 mock worker yalnizca normalized JSON uretir:

- `scan_id`
- `website_id`
- `status`
- `findings`
- `technologies`
- `artifacts`
- `safety_profile`

Gercek Nuclei, ZAP, WPScan, testssl, httpx veya crawler calistirilmaz.

## Passive Discovery Budget

Phase 03 discovery request seti sinirlidir:

- Root URL: 1 bounded GET with manual redirect limit.
- Favicon: 1 bounded GET to `/favicon.ico`.
- robots.txt: 1 bounded GET.
- sitemap.xml: 1 bounded GET.
- DNS: A/AAAA/CNAME/MX/NS/TXT/CAA lookup only.
- TLS certificate metadata: handshake-level certificate read.
- WHOIS and reverse DNS: disabled by default and config gated.

No brute force subdomain enumeration, path wordlist, port scan, fuzzing, exploit payload or authentication attempt is allowed in Phase 03.
