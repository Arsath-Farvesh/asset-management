# Supplier Security Register

## Purpose

Track third-party and cloud dependencies with ownership, security posture, and review cadence.

## Register

| Supplier | Service | Data Exposure | Security Owner | Last Review | Next Review | Notes |
|---|---|---|---|---|---|---|
| Railway | Hosting and deployment platform | Service metadata, runtime environment | Platform Owner | 2026-03-13 | 2026-06-13 | Verify org access controls quarterly. |
| PostgreSQL Provider | Database platform | Application and audit records | Data Owner | 2026-03-13 | 2026-06-13 | Verify backup, encryption, and access control settings. |
| npm ecosystem dependencies | Application libraries | Runtime dependencies | Engineering Lead | 2026-03-13 | 2026-04-13 | Run dependency vulnerability review monthly. |

## Mandatory Supplier Checks

- Contractual security obligations documented.
- Access control and MFA enabled where supported.
- Incident notification commitments reviewed.
- Service continuity expectations documented.
