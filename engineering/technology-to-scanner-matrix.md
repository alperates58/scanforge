# Technology to Scanner Matrix

ScanForge scanner secimi teknoloji fingerprint sonucuna gore yapilir. Phase 04 plugin tabanli rule engine confidence, quality ve graph uretir; gercek scanner calismaz.

## Model

`scanner_capabilities` alanlari:

- `technology_key`: normalize teknoloji anahtari, ornek `wordpress`, `laravel`, `nginx`.
- `scanner_key`: ileride baglanacak adapter, ornek `nuclei`, `wpscan`, `headers-dns`.
- `template_group`: template veya kontrol grubu.
- `scan_module`: urun modulu, ornek `framework-cves`, `cms-inventory`, `edge-posture`.
- `min_confidence`: 0-100 technology confidence esigi.
- `min_version`, `max_version`, `supported_versions`: version-aware scanner/template secimi.
- `enabled`: capability aktif mi.
- `safe_default`: varsayilan safe scan planina dahil edilebilir mi.
- `priority`: planner icin scanner oncelik sinyali.
- `estimated_duration_seconds`, `estimated_requests`, `estimated_cpu`, `estimated_memory_mb`: scheduler ve quota tahmini.
- `safe_mode`: bu capability safe mode planina alinabilir mi.
- `description`: operator tarafindan okunabilir aciklama.

## Runtime Resolver

`CapabilityResolver` DB kayitlarini okur; DB bos ise `config/scanner_capabilities.php` fallback olarak kullanilir. Resolver akisi:

Technology fingerprint -> capability -> recommended scanner -> template group -> priority -> estimated cost -> safe mode.

Resolver scanner motoru calistirmaz. Sadece Phase 05+ orchestrator icin planlanabilir, audit edilebilir karar objesi uretir.

## Default Matrix

| Technology | Scanner | Template Group | Module | Safe |
| --- | --- | --- | --- | --- |
| laravel | nuclei | laravel/* | framework-cves | yes |
| wordpress | wpscan | core/plugins/themes | cms-inventory | yes |
| nginx | nuclei | nginx/* | server-hardening | yes |
| apache | nuclei | apache/* | server-hardening | yes |
| nextjs | nuclei | nextjs/* | framework-cves | yes |
| aspnet | nuclei | iis/aspnet/* | framework-cves | yes |
| cloudflare | headers-dns | cloudflare-checks | edge-posture | yes |
| php | nuclei | php/* | language-cves | yes |

## Phase 04 Rule Evidence

Phase 04 `TechnologyFingerprintEngine` plugin registry uzerinden rule group calistirir. Her matched rule immutable `technology_evidences` satiri uretir.

Source priority confidence hesaplamasina katilir:

- `generator_meta`: 95
- `header` / `server`: 80
- `cookie`: 75
- `dns` / `response`: 70
- `html` / `body`: 60
- `redirect`: 55
- `favicon`: 50
- `js_asset`: 45

Ilk plugin kapsami:

- Cloudflare, Fastly, CloudFront, Akamai, Bunny, Vercel, Netlify, Azure Front Door, Google Cloud CDN.
- Nginx, Apache, Caddy, LiteSpeed, OpenResty, IIS.
- Laravel, Symfony, CodeIgniter, WordPress, Drupal, Joomla, Next.js, Nuxt, React, Vue, Angular, ASP.NET, Spring Boot, Express, Django, Flask.

## Scan Plan Output

`ScanPlanService` capability resolver sonucundan `scan_plans` ve `scan_plan_items` uretir:

- `coverage_prediction`: current fingerprints icin beklenen scanner coverage.
- `recommendation_score`: confidence, quality, capability priority ve safe-mode sinyalinden hesaplanir.
- `estimated_runtime_seconds`, `estimated_requests`, `estimated_cpu`, `estimated_memory_mb`: worker scheduler icin maliyet tahmini.
- `safe_mode=true`: Phase 04 planlari sadece guvenli ve pasif/allowlisted kontroller icin hazirlanir.

## Safety Rules

- Matrix kaydi scanner calistirma izni degildir; scan gate her zaman verified website ve consent ister.
- Confidence dusukse module secimi deferred kalir veya passive kontrollerle sinirlanir.
- WordPress icin brute force, password spray ve credential stuffing hicbir fazda varsayilan module degildir.
- Cloudflare kaydi origin bypass denemesi degil, header/DNS posture kontrolu icindir.

## Next Phases

- Phase 05 orchestrator bu matrisi ve `scan_plan_items` kayitlarini job contract'a cevirecek.
- Phase 06/07 tool adapter'lari matrix kayitlarini safe template allowlist ile birlestirir.
