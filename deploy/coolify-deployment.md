# Coolify Deployment

## DNS
Recommended:
security.alperates.com.tr or scanforge.alperates.com.tr

Cloudflare:
- A/CNAME record to Coolify proxy target
- Full Strict SSL if origin cert configured

## Coolify
1. New Resource -> GitHub Repository
2. Select ScanForge repo
3. Docker Compose deployment
4. Add ENV values from `.env.example`
5. Configure persistent volume for Postgres
6. Deploy

## Redeploy
Push to GitHub -> Coolify redeploy.

## Production Notes
- Worker containers should not be privileged.
- Scanner tools should run with resource limits.
- Backups for PostgreSQL.
- Rotate DeepSeek API key if exposed.
