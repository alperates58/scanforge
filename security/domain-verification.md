# Domain Verification

## DNS TXT
User creates:
scanforge-verify=<token>

## HTML File
User uploads:
/.well-known/scanforge-verification.txt
with token content.

## Verification Lifecycle
- pending_verification
- verified
- expired_verification optional

Re-check verification before deep/authenticated scans.
