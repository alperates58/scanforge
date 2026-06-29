# Codex Master Prompt - ScanForge

You are building ScanForge, a premium AI-assisted web security audit platform.

Read all repository markdown files before changing code, especially:
- README.md
- roadmap/product-roadmap.md
- phases/*.md
- engineering/*.md
- scanner/*.md
- ai/*.md
- security/*.md
- deploy/*.md
- design/*.md

Rules:
1. Implement phase by phase. Do not skip phases.
2. Keep scan behavior safe by default.
3. Active scans require verified domains.
4. Do not add destructive exploit behavior.
5. Store raw scanner output and normalized findings separately.
6. Make UI premium, clean, white/gray/blue.
7. Every scanner integration must have timeout, rate limit and error handling.
8. DeepSeek AI must analyze only provided findings, never invent vulnerabilities.
9. Ensure Docker/Coolify deployment remains working.
10. Commit after each completed phase with clear message.

Start with Phase 01 only. After finishing, report changed files, how to run, and next phase.
