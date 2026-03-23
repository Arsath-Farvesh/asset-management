# ISO/IEC 27001 Readiness Evidence

## Scope

This document maps implemented technical controls in the Asset Management project to relevant ISO/IEC 27001:2022 Annex A themes and records objective repository evidence.

## Control Mapping

### Access Control and Identity

- Control intent: Enforce authenticated access and role-based authorization.
- Implementation evidence:
  - Session-based authentication and role checks in [src/middleware/auth.js](src/middleware/auth.js).
  - Auth routes protected for privileged actions in [src/routes/auth.js](src/routes/auth.js).
  - Admin-only protection for diagnostics endpoint in [src/routes/health.js](src/routes/health.js).
- Verification evidence:
  - Unauthenticated access tests in [__tests__/integration/auth.routes.test.js](__tests__/integration/auth.routes.test.js).

### Secure Session and Request Protection

- Control intent: Protect sessions and state-changing requests.
- Implementation evidence:
  - Secure cookie flags and session store in [server.js](server.js).
  - CSRF protection middleware and token route in [server.js](server.js) and [src/routes/health.js](src/routes/health.js).
  - Request correlation ID middleware in [src/middleware/security.js](src/middleware/security.js).
- Verification evidence:
  - Middleware behavior tests in [__tests__/unit/security.middleware.test.js](__tests__/unit/security.middleware.test.js).

### Secure Configuration and Boundary Protection

- Control intent: Restrict origin access and harden browser execution policy.
- Implementation evidence:
  - Production CORS fail-closed behavior when allowlist is absent in [server.js](server.js).
  - CSP compatibility/strict modes and report-only rollout support in [server.js](server.js).
  - Deployment configuration guidance in [RAILWAY_DEPLOYMENT_RUNBOOK.md](RAILWAY_DEPLOYMENT_RUNBOOK.md).
  - Environment variable definitions in [.env.example](.env.example).

### Logging, Monitoring, and Traceability

- Control intent: Maintain usable logs while redacting sensitive data.
- Implementation evidence:
  - Structured logging and redaction in [src/config/logger.js](src/config/logger.js).
  - Request ID propagation in [src/middleware/security.js](src/middleware/security.js).
  - Health check endpoints in [src/routes/health.js](src/routes/health.js).

### Event Recording and Asset Change Accountability

- Control intent: Record create/update/delete activity for traceability.
- Implementation evidence:
  - Audit table creation in [migrations/20260307000002_audit_logs.js](migrations/20260307000002_audit_logs.js).
  - Audit writes for create/update/delete/bulk-delete in [src/services/assetService.js](src/services/assetService.js).
  - Actor context propagation from HTTP layer in [src/controllers/assetController.js](src/controllers/assetController.js).
- Verification evidence:
  - Audit write unit test in [__tests__/unit/assetService.test.js](__tests__/unit/assetService.test.js).

### Error Handling and Information Leakage Prevention

- Control intent: Avoid exposing internal details to external clients.
- Implementation evidence:
  - Production-safe generic 5xx response behavior in [src/middleware/security.js](src/middleware/security.js).
- Verification evidence:
  - Error handling tests in [__tests__/unit/security.middleware.test.js](__tests__/unit/security.middleware.test.js).

## Release and Verification Evidence

- Test command: npm test -- --runInBand
- Current status: all test suites passing after hardening updates.

## Residual Gaps for Full Certification

The following are typically required for formal certification but are outside code-level implementation:

1. Approved ISMS policy set and governance records.
2. Statement of Applicability (SoA) and control justification.
3. Risk register with treatment plans and ownership.
4. Incident response procedure and exercise records.
5. Supplier security and business continuity evidence.
6. Internal audit and management review records.

## Recommended Next Compliance Steps

1. Build a formal ISMS evidence pack alongside this technical evidence document.
2. Enable CSP strict mode in report-only first, then enforce after inline script/style migration.
3. Add integration tests for audit-log persistence across all mutation routes.
4. Add retention and access policy for log files aligned with organizational compliance requirements.
