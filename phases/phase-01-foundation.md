# Phase 01 - Foundation

## Goal

Laravel backend, React dashboard, Docker Compose, Postgres, Redis, queue ve scanner mock contract ile calisabilir temel platformu kur.

## Deliverables

- `GET /api/health`
- `GET /api/dashboard/summary`
- Dashboard shell at `/dashboard`
- Temel domain models and migrations
- Mock scanner worker
- `.env.example` and README local setup

## Acceptance

- `docker compose up --build` servisleri baslatir.
- Migration calisir.
- Scanner gercek guvenlik araci calistirmaz.
- Active scan kapisi verified domain zorunlulugunu mimari olarak icerir.
