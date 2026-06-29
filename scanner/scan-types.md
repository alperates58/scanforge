# Scan Types

## Passive Scan
- DNS
- WHOIS/domain age
- SSL cert
- HTTP headers
- technology hints
No crawl beyond root/sitemap.

## Standard Scan
- Passive + safe Nuclei + ZAP baseline
- Limited crawl
- CMS detection

## Deep Scan
- Standard + deeper crawl + JS endpoint extraction + parameter discovery
- Still non-destructive

## Authenticated Scan
- User provides test account/cookie
- Session and access control checks
- Never use real admin account unless user insists and risk accepted
