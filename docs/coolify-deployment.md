# Coolify Deployment

ScanForge production deployment icin Docker Compose tabanli Coolify akisi hedeflenir. Phase 01 compose local development icindir; production hardening Phase 11 ve Phase 12'de tamamlanir.

## Required Services

- Backend API container.
- Queue worker container.
- Frontend container.
- Scanner worker container.
- PostgreSQL volume.
- Redis service.
- Optional artifact/report volume.

## Environment

Coolify ortam degiskenleri `.env.example` ile ayni isimleri kullanmalidir. Secret degerler repo icinde tutulmaz.

Minimum required:

- `APP_KEY`
- `DB_*`
- `REDIS_*`
- `QUEUE_CONNECTION=redis`
- `ALLOW_UNVERIFIED_DOMAINS=false`
- `DEEPSEEK_API_KEY` production AI fazinda

## Production Boundaries

- Scanner container privileged olmamalidir.
- Docker socket mount edilmemelidir.
- Host network kullanilmamalidir.
- Scanner CPU/memory limitleri Phase 11'de uygulanir.
- Postgres backup ve restore proseduru tanimlanir.

## Health Checks

- Backend: `/api/health`
- Frontend: HTTP root or `/dashboard`
- Queue: worker process heartbeat
- Scanner: mock/adapter readiness endpoint or periodic heartbeat artifact
