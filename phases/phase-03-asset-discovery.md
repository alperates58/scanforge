# Phase 03 - Asset Discovery

## Goal

Verified website icin guvenli pasif profil, temel attack surface bilgisi, ilk teknoloji ipuclari ve dashboard-ready discovery skorunu uret.

## Deliverables

- `asset_discoveries` run/timeline/metrics tablosu.
- DNS records: A/AAAA/CNAME/MX/NS/TXT/CAA normalized storage.
- IP observations: public/private kontrolu, IP version, provider hint.
- HTTP fingerprint snapshot: status, headers, raw headers, body SHA-256, favicon SHA-256, HTML lang/doctype/size/title/description/generator.
- Security header matrix: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy, COEP, COOP, CORP.
- Cookie observations: name/domain/path/Secure/HttpOnly/SameSite/expires/persistent/host-only. Cookie values are not stored.
- Redirect observations: ordered `from_url`, `to_url`, `status_code`.
- SSL certificate metadata: issuer, subject, SAN, expiry, SHA-256 fingerprint.
- robots.txt and sitemap existence with sensitive-looking robots hints only; no path probing.
- Passive technology hints: CDN, reverse proxy/server, framework/CMS hints at 30-70 confidence.
- Passive findings for missing headers, weak cookie attributes, server exposure, sensitive robots hints and SSL expiry.
- Discovery score 0-100 and `analysis_required=true` for Phase 09 AI queue preparation.
- Frontend website detail screen with asset summary, discovery history, passive findings and technology hints.

## Acceptance

- Discovery requires verified ownership and workspace membership.
- Private/reserved/internal DNS resolution blocks HTTP/TLS probing.
- Redirects are bounded and cannot leave the verified root domain.
- No Nuclei, ZAP, WPScan, testssl, httpx, katana, subfinder, brute force or exploit payload runs.
- Discovery request budget'e uyar: root URL, favicon, robots, sitemap, DNS, TLS metadata and optional gated WHOIS/reverse DNS.
- Sonuclar website detail ve dashboard kartlarina yansir.
- Backend feature tests cover discovery gate, observations, private IP block, redirect limit, passive findings, technology hints, asset summary and workspace isolation.

## API

- `POST /api/websites/{id}/discoveries`
- `GET /api/websites/{id}/discoveries`
- `GET /api/websites/{id}/discoveries/{discoveryId}`
- `GET /api/websites/{id}/assets/summary`

## Out of Scope

- Active scanner orchestration.
- Deep crawler or asset brute force.
- Authenticated scan.
- AI/DeepSeek call.
- CVE/template based scanning.
