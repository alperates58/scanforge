# Phase 04 - Technology Fingerprinting Engine

## Goal

Verified website icin Phase 03 passive observation verisinden guvenli, plugin tabanli teknoloji inventory, kanit modeli, teknoloji graph'i ve safe scan plan tahmini uretmek.

## Scope

- Gercek Nuclei, ZAP, WPScan, testssl, httpx, katana, subfinder veya benzeri scanner motoru calistirilmaz.
- Yeni HTTP crawling/path brute force yapilmaz; engine Phase 03 snapshot'larini ve discovery sirasinda eldeki body sample'i kullanir.
- AI cagrisi yapilmaz; `analysis_required=true` ve `analysis_version` ile Phase 09 hazirligi yapilir.

## Architecture Decisions

- `FingerprintPluginInterface`, `PluginLoader`, `PluginRegistry` merkezi plugin mimarisini olusturur.
- `FingerprintRule`, `RuleGroup`, `RuleEvaluator` rule engine katmanidir. Bir teknoloji birden fazla rule ile skorlanir.
- Source priority confidence hesaplamasina katilir: generator meta 95, header/server 80, cookie 75, HTML/body 60, JS asset 45, favicon 50.
- `confidence_score` detection guvenini, `quality_score` kanit cesitliligi ve kanit sayisini ifade eder.
- `TechnologyEvidence` immutable satirdir; update/delete yoktur.
- `FingerprintHistory` teknoloji version/confidence degisimlerini saklar.
- `TechnologyRelationship` teknoloji graph edge'lerini saklar.
- `TechnologyConflict` exclusive teknoloji gruplarindaki celiskileri AI/operator yorumuna hazirlar.
- `CapabilityResolver` DB/config capability kaynaklarini birlestirir ve safe scanner/template onerisi uretir.
- `ScanPlan` cost ve coverage prediction ile olusur; execution job degildir.

## Deliverables

- Plugin registry ve ilk pluginler: Laravel, WordPress, Cloudflare, Nginx, PHP, React, Next.js, common web technologies.
- Technology fingerprint CRUD degil, read/run API yuzeyi.
- Technology tree ve scan plan dashboard baslangici.
- AI-ready technology graph JSON export.
- Event bus: `FingerprintCompleted`, `CoverageUpdated`, `TechnologyChanged`, `ScanPlanGenerated`.

## Acceptance

- Verified olmayan website fingerprint calistiramaz.
- Her fingerprint `technology_key`, `confidence_score`, `quality_score`, `analysis_required`, `analysis_version` ile kaydolur.
- Evidence satirlari tek tek gorulebilir ve immutable kalir.
- WordPress gibi cok kanitli teknolojiler daha yuksek quality score alir.
- Capability resolver `recommendation_score` ve maliyet tahmini olan scan plan item'lari uretir.
- Frontend website detail ekraninda Technology Tree, coverage ve son scan plan bilgisi gorunur.

## Next Phase Link

Phase 05 scan orchestrator, Phase 04 `scan_plans` ve `scan_plan_items` kayitlarini gate/queue/job contract katmanina baglayacak. Scanner adapter execution yine safe allowlist, quota, consent ve rate-limit kontrollerinden sonra yapilacak.
