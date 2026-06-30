# Finding Normalization

Tum scanner ve passive discovery ciktilari tek bulgu formatina indirgenir. Phase 07 ile normalize etme, correlation, risk scoring, source/evidence kaydi ve AI hazirligi merkezi Finding Engine servislerine tasindi.

## Required Fields

- `title`
- `severity`: info, low, medium, high, critical
- `confidence`: 0.0-1.0
- `affected_url`
- `source_tool`
- `evidence`

## Optional Fields

- `cwe`
- `cve`
- `cvss`
- `owasp_category`
- `remediation`
- `fingerprint_hash`
- `raw_artifact_id`

## Dedupe Strategy

`correlation_key` ve `dedupe_hash` stable olmalidir. Phase 07 sirali correlation kurallari:

- exact `template_id + affected_url`
- same CVE + same host
- same CWE + same path + same parameter
- same normalized title + same affected component
- header/cookie findings grouped by header/cookie name
- SSL certificate findings grouped by host/cert fingerprint

Duplicate satir acilmaz; `occurrence_count`, `last_seen_at`, source kayitlari ve correlation score guncellenir.

## Canonical Library and Taxonomy

- `canonical_findings`: `normalized_key`, default title/description/remediation/references ve AI summary template tutar.
- `finding_taxonomies`: category, subcategory, OWASP category, ASVS control, CWE ve CAPEC baglamini tutar.
- `findings.canonical_finding_id` ve `findings.finding_taxonomy_id` AI Analyst icin stable referanslardir.

## Risk Formula

Risk skoru 0-100 araligindadir:

`severity*0.35 + confidence*0.15 + exploitability*0.15 + exposure*0.12 + asset_importance*0.10 + cvss*0.10 + kev_bonus - false_positive_penalty - auth_required_penalty`

Priority thresholds: `critical >=85`, `high >=70`, `medium >=40`, `low >=15`, aksi halde `info`.

Risk degisiklikleri `risk_score_histories`, confidence degisiklikleri `confidence_histories` tablosuna yazilir.

## Evidence and Sources

- `finding_sources`: canonical finding'in hangi scanner/job/artifact/template tarafindan goruldugunu saklar.
- `finding_evidences`: AI icin okunabilir preview, mime, sha256 ve raw artifact referansi tutar.
- Raw secret-bearing header/cookie/token degerleri source payload ve evidence preview icinde redakte edilir.

## Suppression

Ignored veya false positive kararlarindan `suppression_rules` uretilebilir. Rule scanner/template/host kapsaminda ve opsiyonel `expires_at` ile calisir.

## Safety

Evidence alani secrets icermemelidir. Raw response icinde cookie, auth token veya password gorulurse redact edilmelidir.
