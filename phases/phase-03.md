# Phase 03 - Domain Verification

## Goal
Sadece yetkili domainlerde tarama.

## Methods
- DNS TXT: scanforge-verify=<token>
- HTML file: /.well-known/scanforge-verification.txt
- Meta tag optional

## Acceptance
- Doğrulanmamış hedeflerde aktif tarama yapılamaz.
- Passive preview yapılabilir ama rate limitli.
