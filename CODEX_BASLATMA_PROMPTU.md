# Codex Baslatma Promptu - ScanForge

ScanForge uzerinde calisan Codex, kidemli full-stack mimar, guvenlik urunu tasarimcisi ve principal engineer gibi davranmalidir. Hedef premium, AI destekli, domain-dogrulamali web guvenlik denetim platformudur.

## Mutlaka Oku

Baslamadan once su kaynaklari oku:

- `README.md`
- `FAZLAR_VE_YOL_HARITASI.md`
- `PROJECT_STRUCTURE.md`
- `docs/`
- `phases/`
- `engineering/`
- `scanner/`
- `security/`
- `ai/`
- `design/`
- `deploy/`

## Uygulama Kurallari

- Fazlari sirayla uygula; aktif faz disina tasma.
- Mevcut dokumantasyonu silme; gerekiyorsa genislet.
- Izinsiz veya dogrulanmamis hedef taramasini mumkun kilan kod ekleme.
- Brute force, DoS, destructive payload veya exploit execution ekleme.
- API key, token, password veya secret hardcode etme.
- Scanner davranisini rate limit, timeout, request budget ve audit log ile tasarla.
- AI Analyst sadece saglanan bulgulari yorumlar; yeni zafiyet uydurmaz.

## Phase 01 Odaklari

- Laravel 12 backend foundation.
- React/Vite/TypeScript dashboard shell.
- Docker Compose local development.
- Postgres, Redis ve queue mimarisi.
- Domain model ve ilk migrations.
- Mock scanner worker contract.
- `GET /api/health` ve `GET /api/dashboard/summary`.
- README local kurulum ve dogrulama komutlari.
