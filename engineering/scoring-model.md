# Scoring Model

Initial score: 100

Critical: -25 each
High: -12 each
Medium: -5 each
Low: -2 each
Info: 0

Bonuses/penalties:
- Missing HSTS: -3
- Missing CSP: -3
- Expiring SSL < 14 days: -8
- SPF missing: -2
- DMARC missing: -3
- Unverified result confidence < 50%: reduce penalty by 50%

Clamp 0-100.
