# Security Boundaries

ScanForge sadece kullanicinin sahip oldugu veya yazili yetki aldigi domainlerde kullanilmak uzere tasarlanir. Bu belge sistemin uygulama ve scanner seviyesinde korumasi gereken sinirlari tanimlar.

## Hard Boundaries

- Active scan icin website status `verified` olmak zorundadir.
- Asset discovery icin website ownership verified olmak zorundadir.
- Kullanici scan oncesi sahiplik/yetki consent'ini vermelidir.
- Brute force, credential stuffing, DoS/stress test, exploit chain ve state-changing payload yasaktir.
- Scanner worker dogrudan rastgele hedef kabul etmez; backend tarafindan olusturulan job contract'ini bekler.
- Secrets loglanmaz: password, cookie, token, auth header ve API key redact edilir.
- Verification token plaintext olarak veritabaninda saklanmaz; `verification_token_hash` tutulur.
- Authenticated scan credential payload'lari Laravel encrypted cast ile saklanir; Phase 02'de authenticated scan calismaz.
- Website registry localhost, loopback, RFC1918/private, reserved, link-local, metadata IP ve internal host suffix'lerini reddeder.
- Discovery sirasinda DNS public gorunse bile private/reserved IP tespit edilirse HTTP/TLS probing durur ve bulgu uretilir.

## Safe Defaults

- `ALLOW_UNVERIFIED_DOMAINS=false`
- `SCAN_SAFE_MODE=true`
- `DISCOVERY_WHOIS_ENABLED=false`
- `DISCOVERY_REVERSE_DNS_ENABLED=false`
- Concurrent scan limiti workspace basina dusuk tutulur.
- Same target cooldown standard/deep scan icin uygulanir.
- External command'lar icin timeout ve resource limit zorunludur.

## Audit Points

- Website added.
- Verification token generated and checked.
- Scan requested, blocked, started, completed or failed.
- Asset discovery requested, completed, failed or blocked.
- Scanner command summary without secrets.
- Finding status changed.
- AI analysis generated.

## Ownership Verification

Phase 02 uc sahiplik kaniti destekler:

- DNS TXT: `scanforge-verify=<token>`
- HTML file: `/.well-known/scanforge-verify.txt`
- Meta tag: `<meta name="scanforge-verification" content="<token>">`

HTTP verification kisa timeout, sinirli redirect ve same-host kuralini kullanir. Redirect baska hosta giderse verification basarisiz sayilir.

## Phase 02 Data Guards

- `ownership_verified_at` ve `verification_status=verified` olmadan scan request kabul edilmez.
- `ALLOW_UNVERIFIED_DOMAINS=false` local ve production varsayilanidir.
- `ScanProfile`, `WebsiteCredential` ve `ScannerCapability` modelleri planlama icindir; scanner execution izni vermez.
- Scan status degerleri standarttir: `pending`, `queued`, `starting`, `running`, `paused`, `completed`, `cancelled`, `failed`, `timeout`.
- Finding severity degerleri standarttir: `critical`, `high`, `medium`, `low`, `info`.

## Phase 03 Passive Discovery Guards

- Discovery sadece backend servislerinden calisir; scanner worker veya external security tool calistirmaz.
- Root HTTP request ve `/favicon.ico`, `/robots.txt`, `/sitemap.xml` disinda path probing yapilmaz.
- Redirect chain manuel izlenir, maksimum redirect limiti vardir ve verified root domain disina cikilmaz.
- Favicon hash SHA-256 olarak saklanir; favicon icerigi loglanmaz.
- Security header matrix header var/yok/deger/recommendation seklinde normalize edilir; secret header degerleri audit metadata'ya yazilmaz.
- Cookie observation cookie degerini saklamaz; sadece isim, domain, path ve security flag metadata tutulur.
- Technology hints dusuk confidence planlama sinyalleridir; vulnerability iddiasi sayilmaz.
- `analysis_required=true` AI icin isaretleme yapar; Phase 03 DeepSeek veya baska model cagirmadan biter.

## Phase 04 Fingerprint Guards

- Fingerprint engine sadece verified website ve mevcut passive observation verisiyle calisir.
- Rule pluginleri HTTP crawler, path brute force, exploit veya scanner process baslatmaz.
- `TechnologyEvidence` immutable tasarlanmistir; kanit degistirmek yerine yeni satir uretilir.
- Confidence ve quality skorlar vulnerability iddiasi degildir; scanner planlama ve AI yorumlama sinyalidir.
- `CapabilityResolver` scanner execution izni vermez. Sadece safe-mode scan plan onerisi uretir.
- `ScanPlan` ve `ScanPlanItem` kayitlari execution job degildir; Phase 05 gate, consent, quota ve rate limit kontrollerinden gecmeden calistirilamaz.
- Technology graph export AI icin hazirdir ama Phase 04 DeepSeek veya baska model cagirmadan biter.
- Scanner capability cost tahminleri scheduler inputudur; DoS/stress test icin kullanilamaz.

## Phase 04 Audit Points

- `technology_fingerprint.completed`
- `scan_plan.generated`
- `FingerprintCompleted`, `CoverageUpdated`, `TechnologyChanged`, `ScanPlanGenerated` eventleri Phase 09 AI listener'lari icin yayinlanir.

## Phase 05 Orchestration Guards

- Scan baslatma verified website, explicit consent, ready/generated scan plan, quota ve concurrent limit kontrolunden gecmeden job uretmez.
- Ayni website icin scan orchestration Redis lock ile korunur: `scanforge:scan:{website_id}`.
- Phase 05 queue job'lari sadece `MockExecutorService` calistirir; external scanner process baslatmaz.
- Queue onceligi `scan-high`, `scan-normal`, `scan-low` olarak `ScanPlanItem.priority` uzerinden secilir.
- Her job icin execution budget saklanir: `max_requests`, `max_runtime`, `max_memory`.
- Job lifecycle `queued -> starting -> running -> completed|failed|timeout|cancelled` timeline olarak saklanir.
- Job log context'i password, secret, token, cookie, authorization ve api_key alanlarini redakte eder.
- Cancellation cooperative token ve `cancel_requested_at` ile modellenir.
- Deep scan varsayilan kapali: `SCANFORGE_ENABLE_DEEP_SCAN=false`.
- Authenticated scan credential ister ama Phase 05 credential kullanmaz ve scanner'a gondermez.
- Worker heartbeat sadece registry/metrics icindir; hedef secme veya execution izni vermez.
- `ScannerInterface` Phase 06 adapter sozlesmesidir; Phase 05 gercek adapter implementasyonu eklemez.

## Phase Links

- Phase 01 security gate servis iskeletini koyar.
- Phase 02 domain verification'i gercek DNS/HTML check ile tamamlar.
- Phase 03 verified asset discovery ve passive recon modelini ekler.
- Phase 04 plugin tabanli technology fingerprint, immutable evidence, graph ve safe scan plan tahmini ekler.
- Phase 05 scan orchestrator, queue, worker registry, mock executor, timeline/log, retry ve cancellation altyapisini ekler.
- Phase 12 audit review ve hardening kontrollerini genisletir.
