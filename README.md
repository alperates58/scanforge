# ScanForge

ScanForge is a premium, AI-assisted web security audit platform for websites that the user owns or is explicitly authorized to test. The system starts with domain registration and verification, plans safe checks by technology, normalizes findings, and prepares AI Analyst reports from evidence only.

Phase 01 set up the foundation: Laravel 12 API, React/Vite dashboard shell, PostgreSQL, Redis, queue-ready backend, mock scanner worker, and Docker Compose local development. Phase 02 adds Sanctum auth, workspace-scoped websites, ownership verification, safer target validation, mock scan permission gates, and future-ready scanner data models. Phase 03 adds verified passive asset discovery, HTTP fingerprint snapshots, DNS/IP/TLS observations, security header and cookie matrices, passive findings, technology hints, and an asset detail dashboard. Phase 04 adds plugin-based technology fingerprinting, immutable evidence, technology graph export, capability resolution, safe scan plan prediction, and a technology tree UI. Phase 05 adds safe scan orchestration, priority queues, worker registry/heartbeat, distributed lock, retry/cancellation contracts, job timelines/logs, mock executor progress, worker metrics, and future scanner interfaces. Phase 06 adds the scanner adapter registry, safe Nuclei adapter, template policy, execution sandbox, raw artifact manifests, scanner version/metrics tracking, finding dedupe and finding history. Phase 07 adds the central Finding Engine: taxonomy, canonical finding library, source/evidence attachments, scanner-independent correlation, risk scoring, risk/confidence history, suppression rules, website risk rollup, scan deltas and a findings panel.

## Safety Boundary

- Active scanning is designed to require verified domains.
- `ALLOW_UNVERIFIED_DOMAINS=false` is the default.
- Nuclei is disabled by default with `NUCLEI_ENABLED=false` and only runs through orchestrated scan jobs.
- ZAP, WPScan, testssl.sh, httpx, crawlers, brute force, fuzzing, DoS, intrusive and destructive templates remain disabled.
- Scanner output follows the normalized finding contract.
- Finding Engine output is scanner-independent and uses canonical findings, taxonomy and evidence attachments.
- Verification tokens are not stored plaintext; only `verification_token_hash` is persisted.
- Website credentials are stored with Laravel encrypted casts and are not used for real authenticated scans yet.
- Passive discovery is verified-domain only; private/reserved DNS resolution blocks HTTP probing.
- Cookie values are not stored by cookie observations.
- Fingerprint evidence is immutable; new observations create new evidence rows.
- Scan plans are recommendations only and are not execution approval.
- Scanner orchestration resolves adapters through `ScannerRegistry`; mock fallback can remain enabled for non-Nuclei scanner keys.
- Deep scan is disabled by default with `SCANFORGE_ENABLE_DEEP_SCAN=false`.
- Secrets must live in `.env` or deployment environment variables, never in code.

## Main Folders

- `backend/`: Laravel 12 API, models, migrations, queue foundation, safety services.
- `frontend/`: React + Vite + TypeScript + Tailwind dashboard shell.
- `scanner/`: mock worker and scanner result contract.
- `docs/`: architecture, safety, coverage and deployment docs.
- `engineering/`: API, DB, orchestration and normalization contracts.
- `phases/`: implementation phases and acceptance criteria.
- `security/`: domain verification, audit and rate-limit policy.
- `ai/`: DeepSeek prompt and output contracts.
- `design/`: premium dashboard/report wireframes.
- `deploy/`: Coolify and Docker hardening notes.

## Local Setup

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Generate a Laravel app key and paste it into root `.env` as `APP_KEY`.

```bash
cd backend
composer install
php artisan key:generate --show
```

3. Start the local stack:

```bash
docker compose up --build
```

4. Run migrations after the backend container is ready:

```bash
docker compose exec backend php artisan migrate
docker compose exec backend php artisan db:seed --class=ScannerTemplatePolicySeeder
docker compose exec backend php artisan db:seed --class=TemplateManifestSeeder
```

5. Open the services:

- Frontend dashboard: `http://localhost:3003/dashboard`
- Backend health: `http://localhost:8000/api/health`
- Dashboard API: `http://localhost:8000/api/dashboard/summary`

UI routes:

- Login: `http://localhost:3003/login`
- Register: `http://localhost:3003/register`
- Websites: `http://localhost:3003/websites`
- Website asset detail: `http://localhost:3003/websites/{id}`
- Website findings: `http://localhost:3003/websites/{id}` Findings panel

## Useful Commands

```bash
docker compose config
docker compose exec backend php artisan migrate
docker compose exec backend php artisan test
docker compose exec frontend npm run build
docker compose logs -f backend queue scanner
```

## Nuclei Local Setup

The backend and queue image install Nuclei `3.10.0` by default and clone `nuclei-templates` into `/opt/nuclei-templates`.

Nuclei remains off unless explicitly enabled:

```bash
NUCLEI_ENABLED=true
NUCLEI_BINARY_PATH=/usr/local/bin/nuclei
NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates
NUCLEI_MAX_REQUESTS=100
NUCLEI_RATE_LIMIT_PER_SECOND=2
```

Only verified websites with consent and a ready scan plan item can reach the Nuclei adapter. Template policies are seeded into `scanner_template_policies`; blocked tags still override allowed groups.

## Phase 02 API Smoke Test

```bash
curl -s -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Local User\",\"email\":\"local@example.com\",\"password\":\"password-secure\"}"
```

Use the returned token as `Authorization: Bearer <token>` for `/api/websites`, `/api/websites/{id}/verification`, and `/api/dashboard/summary`.

## Phase 03 API Smoke Test

After a website is verified, passive discovery can be started with:

```bash
curl -s -X POST http://localhost:8000/api/websites/1/discoveries \
  -H "Authorization: Bearer <token>"
```

Then read the asset profile:

```bash
curl -s http://localhost:8000/api/websites/1/assets/summary \
  -H "Authorization: Bearer <token>"
```

## Phase 04 API Smoke Test

After a verified website has passive observations:

```bash
curl -s -X POST http://localhost:8000/api/websites/1/fingerprint \
  -H "Authorization: Bearer <token>"

curl -s -X POST http://localhost:8000/api/websites/1/scan-plans \
  -H "Authorization: Bearer <token>"

curl -s http://localhost:8000/api/websites/1/technology-graph \
  -H "Authorization: Bearer <token>"
```

## Phase 05 API Smoke Test

After a verified website has a ready scan plan:

```bash
curl -s -X POST http://localhost:8000/api/websites/1/scans \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"scan_type\":\"standard\",\"safety_mode\":\"standard\",\"consent_accepted\":true}"

curl -s http://localhost:8000/api/websites/1/scans \
  -H "Authorization: Bearer <token>"
```

## Phase 01 Acceptance

- Docker Compose defines backend, queue, frontend, scanner, PostgreSQL and Redis.
- Backend exposes `/api/health` and `/api/dashboard/summary`.
- Frontend opens a premium dashboard shell at `/dashboard`.
- Core models and migration draft exist for User, Website, DomainVerification, Scan, Finding, TechnologyFingerprint and AiAnalysis.
- Audit log, scan job and raw artifact foundations exist for later phases.
- Scanner worker is mock-only and does not touch external targets.

## Phase 03 Acceptance

- `POST /api/websites/{id}/discoveries` requires a verified website and workspace access.
- Passive discovery stores DNS/IP/HTTP/TLS/WHOIS/subdomain observations.
- HTTP observation stores favicon SHA-256, body SHA-256, HTML metadata and raw response header JSON.
- Security headers, cookies and redirect chains are normalized into dedicated tables.
- Passive findings and 30-70 confidence technology hints are generated without active scanner tools.
- `/websites/{id}` shows discovery score, asset summary, discovery history, passive findings and technology hints.

## Phase 04 Acceptance

- `POST /api/websites/{id}/fingerprint` requires verified ownership and workspace access.
- Fingerprints store confidence, quality, CPE candidates, immutable evidence and AI analysis version.
- Technology relationships and conflicts are modeled for AI-ready graph export.
- `POST /api/websites/{id}/scan-plans` creates safe recommendation items with coverage and cost prediction.
- `/websites/{id}` shows Technology Tree and latest scan plan metadata.

## Phase 05 Acceptance

- `POST /api/websites/{id}/scans` requires verified ownership, consent, quota, concurrency capacity and a ready/generated scan plan.
- Scan plan items create priority queued `ScanJob` rows with retry policy, execution budget and cancellation token.
- `ExecuteScanJob` runs mock-only lifecycle and writes timeline, logs, worker heartbeat and mock raw artifact records.
- `/websites/{id}` shows scan status, progress, selected plan, safety mode and job table.

## Phase 06 Acceptance

- `ExecuteScanJob` resolves scanner adapters through `ScannerRegistry`.
- `NucleiScanner` implements `ScannerInterface` and runs only when `NUCLEI_ENABLED=true`.
- Template policy allowlist blocks destructive, intrusive, DoS, fuzzing, brute-force and aggressive exploit groups.
- Nuclei JSONL creates `RawArtifact`, `ArtifactManifest`, normalized findings and scanner metrics.
- Duplicate findings update `last_seen_at` and `occurrence_count` instead of creating new rows.
- `/websites/{id}` shows finding mini-list, severity badge, template ID and raw evidence availability for scan results.

## Phase 07 Acceptance

- Nuclei JSONL and passive findings pass through `FindingNormalizationService`.
- Canonical finding, taxonomy, source, evidence, risk history and confidence history records are created.
- Duplicate/correlated findings update `occurrence_count`, `last_seen_at` and `correlation_score`.
- Findings API supports severity, priority, status, scanner, CVE and search filters.
- Status changes create `finding_events`; ignored/false-positive can create suppression rules.
- Website risk rollup updates `risk_score`, `critical_count`, `high_count` and `risk_trend`.
- `/websites/{id}` shows the Findings panel and detail drawer.
