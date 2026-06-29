# ScanForge Project Structure

Bu dosya repo icindeki klasorlerin teknik sahipligini ve sinirlarini tanimlar. Amac, Phase 01'den itibaren backend, frontend, scanner ve deploy katmanlarinin birbirine karismadan buyumesidir.

## Root

- `README.md`: local kurulum, servis URL'leri ve faz raporu.
- `.env.example`: local ve production icin secret icermeyen env sablonu.
- `docker-compose.yml`: local development servis topolojisi.
- `FAZLAR_VE_YOL_HARITASI.md`: urun ve teknik faz sirasi.
- `CODEX_BASLATMA_PROMPTU.md`: Codex icin guvenli uygulama promptu.

## Application Folders

- `backend/`: Laravel 12 API, Eloquent modeller, migrations, queue, auth, verification, asset discovery ve servis siniflari.
- `frontend/`: React, Vite, TypeScript, Tailwind dashboard.
- `scanner/`: mock worker, scanner job/result contract, ileride tool adapter'lari.
- `ai/`: AI analyst prompt ve JSON output contract dokumantasyonu.

## Documentation Folders

- `docs/`: karar dokumanlari; mimari, guvenlik sinirlari, scanner safety ve deployment.
- `engineering/`: API, database, orchestration ve normalization teknik sozlesmeleri.
- `security/`: domain dogrulama, audit logging, rate limit ve etik politika.
- `scanner/`: scanner tool matrisi, scan tipleri ve normalize output kurallari.
- `design/`: dashboard ve rapor UI wireframe'leri.
- `phases/`: faz bazli uygulama hedefleri ve kabul kriterleri.

## Ownership Rules

- Backend, scanner'a dogrudan shell command gondermez; queue/job contract uzerinden is ister.
- Frontend, scanner'a direkt baglanmaz; tum veri backend API uzerinden gelir.
- Scanner worker, sadece backend tarafindan dogrulanmis ve rate limitlenmis isleri kabul eder.
- Asset discovery, scanner worker'dan ayridir; verified website icin backend-local pasif DNS/HTTP/TLS metadata toplar.
- Deploy dosyalari secret saklamaz; secret degerleri `.env` veya Coolify environment olarak verilir.
