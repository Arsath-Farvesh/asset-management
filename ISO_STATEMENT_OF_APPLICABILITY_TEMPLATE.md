# ISO/IEC 27001 Statement of Applicability (SoA) Starter

## Document Control

- Organization: [Enter organization name]
- ISMS Scope: [Define organizational, technical, and physical scope]
- Version: 0.1-draft
- Owner: [CISO / ISMS Manager]
- Approved by: [Management]
- Effective date: [YYYY-MM-DD]
- Review cycle: [Quarterly / Semiannual]

## Method

For each control domain below:

1. Determine applicability based on risk assessment and legal/regulatory context.
2. Mark status as Applicable or Not Applicable.
3. If Applicable, document implementation evidence and owner.
4. If Not Applicable, provide a business/risk-based justification.

## SoA Matrix (Starter)

| Control Theme | Applicable (Y/N) | Justification | Implementation Status | Evidence Reference | Owner |
|---|---|---|---|---|---|
| Information security policies | Y | Required for ISMS governance | Partial | [Add policy docs] | [Name] |
| Access control and least privilege | Y | User/admin access separation needed | Implemented | src/middleware/auth.js, src/routes/auth.js | [Name] |
| Identity lifecycle management | Y | Joiner/mover/leaver controls required | Partial | [Add HR/IT process evidence] | [Name] |
| Cryptographic controls | Y | Password/session security required | Implemented | src/services/authService.js, server.js | [Name] |
| Logging and monitoring | Y | Incident detection and traceability | Implemented | src/config/logger.js, src/middleware/security.js | [Name] |
| Event/audit trail recording | Y | Asset mutation accountability required | Implemented | migrations/20260307000002_audit_logs.js, src/services/assetService.js | [Name] |
| Vulnerability and patch management | Y | Ongoing maintenance required | Partial | [Add process and cadence evidence] | [Name] |
| Secure development lifecycle | Y | Change assurance and quality gates | Partial | package.json, __tests__/ | [Name] |
| Supplier/cloud security | Y | Railway/postgres and third-party dependencies | Partial | RAILWAY_DEPLOYMENT_RUNBOOK.md | [Name] |
| Incident response | Y | Required for breach handling | Missing/Planned | [Add incident playbook] | [Name] |
| Business continuity and DR | Y | Service availability requirements | Partial | [Add BCP/DR evidence] | [Name] |
| Compliance obligations | Y | Contractual and legal obligations | Partial | [Add legal register] | [Name] |

## Existing Technical Evidence (Current Repository)

- ISO readiness mapping: ISO_READINESS_EVIDENCE.md
- Deployment hardening runbook: RAILWAY_DEPLOYMENT_RUNBOOK.md
- Environment baseline: .env.example
- Security middleware and error handling: src/middleware/security.js
- Authentication and authorization middleware: src/middleware/auth.js
- Asset audit logging implementation: src/services/assetService.js
- Audit log schema migration: migrations/20260307000002_audit_logs.js

## Required Non-Code Evidence to Complete SoA

1. Approved security policy set.
2. Risk assessment and risk treatment plan.
3. Legal/regulatory register.
4. Supplier assessment records.
5. Incident response procedure and test records.
6. Internal audit and management review minutes.

## Approval

- Prepared by: ______________________ Date: __________
- Reviewed by: ______________________ Date: __________
- Approved by: ______________________ Date: __________
