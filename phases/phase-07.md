# Phase 07 - Nuclei Integration

## Goal
Bilinen CVE ve misconfiguration şablonlarıyla güvenli tarama.

## Rules
- Sadece verified domain
- severity info/low/medium/high/critical
- destructive templates kapalı
- rate limit aktif
- template update ayrı job

## Acceptance
- Nuclei JSON çıktısı normalize edilir.
