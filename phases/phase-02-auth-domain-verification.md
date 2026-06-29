# Phase 02 - Auth, Ownership Verification and Scan Gate

## Goal

Kullanici, workspace, guvenli website registry, ownership verification ve mock scan permission gate akisini tamamla. Bu faz gelecekteki scanner ve SaaS data modelini hazirlar, ancak gercek guvenlik araci calistirmaz.

## Deliverables

- Laravel Sanctum register/login/logout/me endpoint'leri.
- Register sirasinda default `Personal Workspace` ve owner membership.
- Workspace quota alanlari: `plan_name`, `monthly_scan_limit`, `concurrent_scan_limit`, `scans_used_this_month`.
- Website CRUD: URL normalization, public target guard, duplicate host engeli, notes/tags/environment/importance.
- Ownership verification alanlari: `ownership_verified_at`, `verification_method`, `verification_token_hash`, `verification_last_checked_at`, `verification_status`.
- DNS TXT, HTML file ve meta tag verification check.
- Plaintext verification token saklamama; audit loglarda token/secret redaction.
- ScanProfile, WebsiteCredential ve ScannerCapability modelleri.
- Scan status, finding severity, technology confidence, AI cost metadata ve scan pipeline milestone alanlari.
- Protected `POST /api/websites/{id}/scans` mock scan endpoint'i.

## Acceptance

- Kullanici kayit olup token alabilir ve `/api/me` ile workspace gorebilir.
- Kullanici website ekleyebilir; URL normalize edilir ve private/internal hedefler reddedilir.
- Duplicate `workspace_id + normalized_host` engellenir.
- Verification endpoint'i uc yontem icin token talimatlarini dondurur; token DB'de plaintext tutulmaz.
- DNS TXT, HTML file veya meta tag basariliysa website verified olur.
- Verified olmayan website scan request'i `domain_not_verified` ile reddedilir.
- Verified website consent ile mock scan ve mock scan job olusturur.
- Workspace isolation baska kullanicinin website'ina erisimi engeller.

## Out of Scope

- Nuclei, ZAP, WPScan, testssl, httpx, katana, subfinder calistirma.
- Authenticated scan calistirma.
- ScanProfile ve WebsiteCredential UI.
- Public Suffix List tabanli tam root domain extraction.
