# ScanForge Architecture

ScanForge, web varliklarini guvenli sekilde analiz eden cok bilesenli bir platformdur. Mimari, UI ile scanner execution arasina backend ve queue katmani koyarak dogrulama, rate limit ve audit kontrollerini merkezi hale getirir.

## Components

- **Frontend**: React/Vite dashboard; website, scan, finding ve AI analysis verisini backend API'den okur.
- **Backend API**: Laravel 12; auth, website registry, verification, scan planning, findings, reports ve AI orchestration.
- **Asset Discovery Services**: verified website icin DNS, HTTP snapshot, TLS, optional WHOIS, passive finding ve technology hint uretir.
- **Queue Layer**: Redis tabanli Laravel queue; scanner ve AI islerinin siralanmasi icin kullanilir.
- **Scanner Worker**: Phase 01'de mock worker; ileride Nuclei, ZAP, testssl, httpx ve CMS adapter'lari eklenir.
- **PostgreSQL**: kullanici, website, verification, scan, finding, technology fingerprint ve audit log icin source of truth.
- **Artifact Storage**: raw scanner output ve rapor dosyalari icin kontrollu volume/object storage.

## Data Flow

1. Kullanici website ekler.
2. Backend URL'yi normalize eder ve domain verification token uretir.
3. Kullanici DNS TXT, HTML file veya meta tag ile ownership dogrular.
4. Backend verified website icin passive asset discovery calistirir.
5. Discovery DNS/IP/HTTP/TLS/header/cookie/redirect/technology evidence uretir ve `analysis_required=true` ile AI icin aday isaretler.
6. Active scan sadece verified domain icin planlanir.
7. Scan job Redis queue'ya yazilir.
8. Scanner worker raw artifact ve normalized finding contract'ina uygun sonuc uretir.
9. Backend finding skorlar, AI Analyst icin safe context hazirlar.
10. Frontend dashboard skor, risk ve remediation verisini gosterir.

## Phase Links

- Phase 01 bu bilesenlerin calisabilir iskeletini kurar.
- Phase 02 auth, workspace ve domain verification akisini tamamlar.
- Phase 03 passive asset discovery ve asset dashboard katmanini ekler.
- Phase 05 scanner orchestration'i production kalitesine yaklastirir.
- Phase 11 production deploy ve healthcheck kararlarini tamamlar.
