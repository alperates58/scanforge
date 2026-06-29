# ScanForge Fazlar ve Yol Haritasi

ScanForge fazlari, guvenli ve dogrulanabilir bir web guvenlik denetim platformunu adim adim kurmak icin siralanmistir. Her faz onceki fazdaki mimari sinirlari korur: domain dogrulamasi, rate limit, audit log ve non-destructive scanner davranisi geri alinmaz kararlar olarak kabul edilir.

## Faz Sirasi

1. **Foundation**: Laravel API, React dashboard, Docker Compose, Postgres, Redis, temel domain modeli, mock scanner contract.
2. **Auth ve Domain Verification**: kullanici, workspace, domain ekleme ve DNS TXT/HTML file dogrulama akislari.
3. **Asset Discovery**: guvenli pasif profil, DNS/IP/HTTP/TLS/header/cookie/redirect gozlemi, ilk teknoloji ipuclari.
4. **Technology Fingerprinting**: Phase 03 ipuclarini daha guclu header, HTML, cookie, path ve imza kanitlariyla pekistirme.
5. **Scan Orchestrator**: job planlama, timeout, retry, progress, artifact yazimi.
6. **Nuclei Integration**: sadece safe template setleriyle verified domain tarama.
7. **ZAP Integration**: OWASP ZAP baseline, sinirli spider, destructive active attack yok.
8. **CMS ve WordPress Scanning**: CMS odakli guvenli kontroller, brute force yok.
9. **AI Analyst DeepSeek**: normalize bulgulardan executive ve teknik rapor uretimi.
10. **Reporting ve Alerts**: HTML/PDF rapor, scan history, kritik bulgu uyarilari.
11. **Coolify Production**: production compose, volumes, backup, healthchecks.
12. **Hardening ve Audit**: izolasyon, secret hygiene, audit review, abuse controls.

## Guvenlik Kararlari

- Active scan sadece `verified` domainlerde calisir.
- `ALLOW_UNVERIFIED_DOMAINS=false` varsayilandir ve local dahil scanner kapilari bunu temel alir.
- Scanner Phase 01-03 arasinda mock result ve passive discovery ile sinirlidir; Nuclei, ZAP, WPScan, testssl, httpx gibi araclar calistirilmaz.
- Her scanner entegrasyonu ileride per-target rate limit, request budget ve timeout ile calismak zorundadir.
- Audit log secrets, password, cookie, token ve raw auth header saklamaz.

## Phase 01 Cikis Kriteri

- `docker compose up --build` local backend, frontend, postgres ve redis servislerini ayaga kaldirir.
- `GET /api/health` uygulama, DB ve Redis durumunu raporlar.
- `GET /api/dashboard/summary` dashboard shell icin baslangic metriklerini verir.
- `/dashboard` premium ScanForge shell ile acilir.
- Temel modeller ve migrations sonraki fazlar icin genisletilebilir durumdadir.

## Phase 03 Cikis Kriteri

- Verified website olmadan asset discovery baslamaz.
- DNS private/reserved IP dondururse HTTP probing durur.
- HTTP snapshot favicon hash, body hash, HTML meta, raw headers, cookies ve redirect chain'i normalized saklar.
- Security header matrix ve cookie observations dashboard/API icin hazirdir.
- Passive technology hints 30-70 confidence ile Phase 04'e girdi uretir.
