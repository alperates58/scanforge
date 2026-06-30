# Phase 07 - Finding Normalization, Correlation and Risk Engine

## Summary

Phase 07, ScanForge finding engine katmanini kurar. Amac farkli kaynaklardan gelen bulgulari canonical modele cevirmek, ayni zafiyeti correlate etmek, risk skorunu hesaplamak, history/source/evidence kayitlarini tutmak ve Phase 09 AI Analyst icin temiz veri hazirlamaktir.

## Backend Scope

- `FindingNormalizationService`: scanner veya passive raw payload'i canonical finding input'una cevirir.
- `FindingCorrelationService`: duplicate/correlated bulgulari tek finding altinda birlestirir ve `correlation_score` hesaplar.
- `FindingRiskEngine`: severity, confidence, exposure, asset importance, CVSS, KEV placeholder, authentication requirement ve false positive risk ile 0-100 risk skoru uretir.
- Canonical library: `canonical_findings` ayni finding tanimini tekrar tekrar uretmeden reuse eder.
- Taxonomy: `finding_taxonomies` category, subcategory, OWASP, ASVS, CWE ve CAPEC baglamini saklar.
- Evidence/source/history: `finding_sources`, `finding_evidences`, `finding_events`, `risk_score_histories`, `confidence_histories`, `finding_deltas`.
- Suppression: `suppression_rules` ignored/false positive kararlarini scanner/template/host bazinda kalici kurala donusturebilir.

## API/UI Scope

- `GET /api/websites/{id}/findings`
- `GET /api/websites/{id}/findings/{findingId}`
- `POST /api/websites/{id}/findings/{findingId}/status`
- `GET /api/websites/{id}/findings/summary`
- Website detail icinde Findings paneli, risk badge, filters, source badges, detail drawer, evidence, remediation, references ve status actions.
- Dashboard risk rollup: open findings, critical/high, resolved, false positive, average risk ve top risky websites.

## Out of Scope

Yeni scanner adapter'i eklenmez. ZAP, WPScan, testssl.sh, httpx, katana, subfinder, ffuf, nmap, brute force, fuzzing ve intrusive scan akislari kapali kalir.
