# Database Schema Draft

Bu belge Phase 06 itibariyla ScanForge veri modelinin kararlarini tanimlar. Tablo kolonlari uygulama migration'lari ile ayni niyeti tasir; production oncesi indeks ve retention politikalari Phase 12'de sertlestirilecektir.

## Identity and Workspace

- `users`: Laravel auth kullanicisi. Password hash Laravel tarafindan uretilir.
- `personal_access_tokens`: Laravel Sanctum API token tablosu.
- `workspaces`: SaaS tenant. `plan_name`, `monthly_scan_limit`, `concurrent_scan_limit`, `scans_used_this_month` alanlari quota temelidir.
- `workspace_members`: user-workspace pivot. Phase 02'de `owner` rolunu kullanir; ekip rolleri sonraki fazlara birakilir.

## Website Ownership

- `websites`: workspace'e ait public hedef kaydi.
- Temel host alanlari: `url`, `scheme`, `host`, `root_domain`, `port`, `normalized_host`.
- Ownership alanlari: `ownership_verified_at`, `verification_method`, `verification_token_hash`, `verification_last_checked_at`, `verification_status`.
- Plaintext verification token saklanmaz. Token APP_KEY tabanli deterministik uretilir, hash DB'de tutulur.
- Yonetim alanlari: `environment`, `importance`, `notes`, `tags`.
- Dashboard alanlari: `security_score`, `risk_score`, `last_scan_score`, `last_scan_at`.
- Phase 03 alanlari: `discovery_completed_at`, `last_observed_at`.

## Verification

- `domain_verifications`: website basina yontem durumlarini tutar.
- Desteklenen yontemler: `dns_txt`, `html_file`, `meta_tag`.
- Token plaintext kolonu yoktur; `verification_token_hash` tutulur.
- `checked_at`, `verified_at`, `last_error`, `evidence` alanlari audit edilebilir sonuc icindir.

## Scan Pipeline

- `scans`: scan request ve pipeline durumunu tutar.
- Status degerleri: `pending`, `queued`, `starting`, `running`, `paused`, `completed`, `cancelled`, `failed`, `timeout`.
- Phase 05 alanlari: `workspace_id`, `scan_plan_id`, `safety_mode`, `request_budget`, `timeout_seconds`, `progress_percent`, job counters, `completed_at`, `cancelled_at`, `duration_ms`, `metadata`.
- Pipeline milestone alanlari Scan uzerindedir: `discovery_completed_at`, `fingerprint_completed_at`, `passive_scan_completed_at`, `deep_scan_completed_at`, `ai_analysis_completed_at`.
- `scan_jobs`: queue/worker seviyesindeki alt isler. Phase 05 alanlari scanner/module/template, priority, retry, timeout, result summary, worker id, lock key, queue name, execution budget, cancellation token ve heartbeat bilgisini tasir. Phase 06 `job_uuid` ile execution sandbox yolunu belirler.
- `scan_workers`: worker capability registry ve heartbeat tablosu. `worker_id`, `supported_scanners`, status, current/max jobs ve metadata tutar.
- `scan_job_timelines`: her job state transition kaydi. AI ve operasyonel timeline icin canonical kayittir.
- `scan_job_logs`: job seviyesinde timestamped log. Context secret redaction ile yazilir.
- `scan_schedules`: gelecekteki scheduler icin cron/timezone/enabled/last_run/next_run alanlari. Phase 05 calistirmaz.
- `scan_profiles`: website icin hazir scan profili temeli. `enabled_modules`, `rate_limit`, `timeout_seconds`, `authenticated`, `is_default` alanlarini tasir.
- `website_credentials`: authenticated scan hazirligi. `encrypted_payload` Laravel encrypted cast ile tutulur; plaintext credential saklanmaz.

## Asset Discovery

- `asset_discoveries`: verified website icin pasif kesif run kaydi. Timeline alanlari: `started_at`, `dns_completed_at`, `http_completed_at`, `ssl_completed_at`, `whois_completed_at`, `completed_at`.
- Discovery metrics: `total_dns_records`, `total_ips`, `total_headers`, `total_cookies`, `total_findings`, `technologies_detected`.
- AI hazirligi: `analysis_required=true` tamamlanan discovery sonucunun Phase 09 AI kuyruguna aday oldugunu gosterir; Phase 03 AI cagrisi yapmaz.
- Kaba skor: `discovery_score` 0-100 arasi HTTPS, TLS, header, cookie ve exposure sinyallerinden hesaplanir.
- `dns_records`: A/AAAA/CNAME/MX/NS/TXT/CAA kayitlarini normalized sekilde saklar.
- `ip_addresses`: public/private kontrolu, IP version, provider hint ve opsiyonel reverse DNS metadata tutar. Reverse DNS varsayilan kapali: `DISCOVERY_REVERSE_DNS_ENABLED=false`.
- `http_observations`: ana sayfa HTTP snapshot'i. Alanlar: `status_code`, `final_url`, `headers`, `response_headers_raw`, `cookies`, `body_hash_sha256`, `favicon_hash`, `html_lang`, `html_doctype`, `html_size_bytes`, `body_title`, `body_description`, `generator_meta`.
- `security_header_observations`: normalize security header matrix. Her header icin `header_key`, `present`, `value`, `recommendation` tutulur. Kapsam: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy, COEP, COOP, CORP.
- `cookie_observations`: cookie session security snapshot'i. Alanlar: `name`, `domain`, `path`, `secure`, `http_only`, `same_site`, `expires_at`, `persistent`, `host_only`.
- `redirect_observations`: redirect chain'i satir bazinda saklar: `order`, `from_url`, `to_url`, `status_code`.
- `ssl_certificates`: TLS sertifika ozeti, SAN, fingerprint ve expiry bilgisi.
- `subdomains`: Phase 03'te brute force yapmadan sadece verified host, `www` varyanti ve sertifika SAN sinyallerini tutar.
- `domain_whois_snapshots`: WHOIS pasif snapshot. Varsayilan kapali: `DISCOVERY_WHOIS_ENABLED=false`.

## Findings, Technology and AI

- `findings`: normalize guvenlik bulgusu. Severity degerleri: `critical`, `high`, `medium`, `low`, `info`. Phase 03'te `scan_id` nullable, `asset_discovery_id` nullable alanlari pasif discovery bulgularini scanner run olmadan saklamak icin vardir.
- Phase 06 finding alanlari: `scanner_key`, `template_id`, `parameter`, `dedupe_hash`, `first_seen_at`, `last_seen_at`, `occurrence_count`, `matched_at`, `description`, `references`, `evidence_json`, `confidence_score`, `false_positive_risk`, `analysis_required`.
- Phase 07 finding alanlari: `workspace_id`, `canonical_finding_id`, `finding_taxonomy_id`, `normalized_title`, `normalized_description`, `risk_score`, `priority`, `resolved_at`, `reopened_at`, `correlation_key`, `correlation_score`, `related_finding_id`, `asset_type`, `asset_id`, `asset_identifier`, `affected_component`, `affected_parameter`, `cve_json`, `cwe_json`, `cvss_score`, `ai_summary`, `analysis_version`, `analysis_status`, `sla_due_at`.
- Finding dedupe fingerprint: correlation rule sonucu uretilen stable key hash'idir. Ayni website icin ayni `dedupe_hash` tekrar gelirse satir tekrar acilmaz; `last_seen_at`, `occurrence_count`, sources ve histories guncellenir.
- Finding status degerleri Phase 07 sonrasi: `new`, `confirmed`, `ignored`, `resolved`, `false_positive`, `reopened`. Eski `open` kayitlari aktif kabul edilir.
- `finding_histories`: finding status gecislerini saklar. Phase 06 Nuclei tekrar gorulen resolved/ignored bulguyu history'de `reopened` olayi olarak kaydeder.
- `finding_events`: Phase 07 canonical lifecycle event tablosu. `old_status`, `new_status`, `reason`, `changed_by_user_id`, `changed_at`.
- `finding_sources`: canonical finding'in scanner/job/artifact/template kaynagini saklar.
- `finding_evidences`: evidence attachment tablosu. `type`, `mime`, `sha256`, `artifact_id`, `thumbnail`, `preview`.
- `finding_taxonomies`: category, subcategory, OWASP category, ASVS control, CWE ve CAPEC.
- `canonical_findings`: normalized key ve default title/description/remediation/references/AI summary template.
- `risk_score_histories`: risk skoru degisimlerini tutar.
- `confidence_histories`: confidence degisimlerini tutar.
- `suppression_rules`: ignored/false-positive kararlarini scanner/template/host kapsaminda kalici hale getirir.
- `finding_deltas`: scan bazinda `new`, `resolved`, `worsened`, `unchanged` sinyali.
- `websites` Phase 07 rollup alanlari: `risk_score`, `critical_count`, `high_count`, `risk_trend`.
- `cve_references`: CVE placeholder tablosu. `cve`, `cvss`, nullable `epss`, nullable `kev`, `vendor`, `product`, `version` tutar. Phase 06 dis veri cekmez.
- `technology_fingerprints`: teknoloji inventory ana kaydi. Phase 04 alanlari: `workspace_id`, `asset_discovery_id`, `technology_key`, `technology_name`, `quality_score`, `cpe_candidates`, `scanner_recommendations`, `analysis_required`, `analysis_version`, `is_active`, `first_detected_at`, `last_detected_at`, `fingerprint_hash`.
- `confidence_score` teknolojinin ne kadar kuvvetle tespit edildigini gosterir; `quality_score` kanit cesitliligi ve kanit sayisini gosterir. Ornek: tek header ile PHP confidence yuksek olabilir ama quality dusuk kalabilir.
- `cpe_candidates` tek string degildir; her aday `{ confidence, source, cpe, version }` seklinde saklanir.
- `technology_evidences`: immutable kanit satirlari. Alanlar: `fingerprint_id`, `source_type`, `source_key`, `source_value`, `confidence`, `raw_data`, `detected_at`. Kanit update/delete edilmez; yeni gozlem yeni satirdir.
- `fingerprint_histories`: version veya confidence degisikliklerini `old_version`, `new_version`, `confidence_old`, `confidence_new`, `detected_at` ile tutar.
- `technology_relationships`: teknoloji graph edge tablosu. Ornek: `cloudflare -> nginx -> php -> laravel`.
- `technology_conflicts`: ayni exclusive grupta yuksek confidence ile gelen celiskileri saklar. Ornek: `apache` ve `caddy` birlikte yuksek confidence ise AI yorumuna hazir conflict uretilir.
- `scanner_capabilities`: technology-to-scanner matrix tablosu. Phase 04 alanlari: `min_version`, `max_version`, `supported_versions`, `priority`, `estimated_duration_seconds`, `estimated_requests`, `estimated_cpu`, `estimated_memory_mb`, `safe_mode`.
- `scan_plans`: teknoloji inventory uzerinden uretilen guvenli scan planlari. `coverage_prediction`, runtime/request/CPU/memory tahminleri ve `safe_mode` alanlarini tasir.
- `scan_plan_items`: onerilen scanner/template modulleri. `recommendation_score` 0-100 arasi oncelik sinyalidir.
- `ai_analyses`: AI Analyst raporu. `prompt_version`, `model_provider`, `model_name`, `input_tokens`, `output_tokens`, `cost_usd`, `duration_ms` maliyet ve performans takibi icindir.

## Phase 06 Scanner Architecture Tables

- `scanner_template_policies`: scanner bazli template allow/deny policy. `scanner_key`, `template_group`, `allowed`, `safety_level`, `blocked_tags`, `allowed_tags`, `reason` alanlarini tutar.
- `scanner_versions`: dashboard icin scanner binary/template version tracking. `status` degerleri ornek: `ok`, `disabled`, `unknown`.
- `template_manifests`: template yonetimi icin manifest placeholder. `template_id`, `group`, `severity`, `tags`, `author`, `signed`, `last_updated`, `deprecated` alanlarini tutar.
- `scanner_metrics`: scanner bazli run metrigi. `runs`, `success`, `failed`, `timeout`, `avg_runtime`, `avg_findings`.
- `artifact_manifests`: `raw_artifacts` yaninda checksum, size, mime, compressed ve retention policy tutar.

## Phase 04 Fingerprint Architecture Tables

- Rule engine DB'ye rule saklamaz; rule ve pluginler kod/config registry uzerinden yuklenir. DB sadece sonuc, kanit, graph ve plan durumunu saklar.
- `analysis_required=true` her fingerprint icin Phase 09 AI okuyucusuna isaret verir; Phase 04 AI cagrisi yapmaz.
- `analysis_version` DeepSeek prompt ve yorumlama formatlarinin surumlenmesi icin fingerprint uzerinde saklanir.
- Bulk upsert `technology_fingerprints` icin `website_id + technology_key` tekilligini kullanir. Evidence bulk insert edilir ve immutable kalir.
- Coverage metadata website `metadata.technology_coverage` altinda dashboard icin cache edilir; canonical veri fingerprint tablosudur.

## Audit and Raw Evidence

- `audit_logs`: user/workspace/action/target metadata. Secret, token, password, cookie, authorization, api_key alanlari redakte edilir.
- `raw_artifacts`: tool veya mock worker ham ciktisi. Phase 05 mock executor `artifact_type=mock_result`, `scanner_key`, `content` ve `sha256` yazar; secret icermez. Phase 06 Nuclei `artifact_type=nuclei_jsonl` yazar ve JSONL icerigi raw request/response olmadan saklar.
