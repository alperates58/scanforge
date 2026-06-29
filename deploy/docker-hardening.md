# Docker Hardening

- Use non-root users inside containers
- Read-only filesystem where possible
- Drop Linux capabilities
- CPU/memory limits for scanner worker
- No Docker socket mount
- No host network mode
- Separate scanner network
- Store raw artifacts in controlled volume
