# ScanForge Backend

Laravel 12 API for ScanForge Phase 01.

## Provides

- `GET /api/health`
- `GET /api/dashboard/summary`
- PostgreSQL migrations for core ScanForge domain models
- Redis queue-ready configuration
- Scan safety gate service for verified-domain enforcement
- Audit log service with secret redaction

## Local

```bash
composer install
php artisan key:generate --show
php artisan migrate
php artisan serve --host=0.0.0.0 --port=8000
```

Docker Compose from the repository root is the preferred local flow.
