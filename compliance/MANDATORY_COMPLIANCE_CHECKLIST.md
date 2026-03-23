# Mandatory Compliance Checklist

## Purpose

This checklist defines the minimum mandatory controls and artifacts for the Asset Management project before production release.

## Governance and Documentation

- [ ] ISMS scope defined and approved.
- [ ] Statement of Applicability maintained and approved.
- [ ] Risk register is current with owners and treatment dates.
- [ ] Incident response runbook approved and exercised.
- [ ] Business continuity and disaster recovery plan approved and tested.
- [ ] Access control policy approved and role matrix documented.
- [ ] Data classification and retention matrix approved.
- [ ] Supplier security register reviewed and accepted.
- [ ] Change management policy and release approvals documented.

## Technical Security Baseline

- [ ] Environment preflight passes in strict mode.
- [ ] Release gate passes (tests + docs lint + compliance checks).
- [ ] CORS allowlist configured for production.
- [ ] SESSION_SECRET uses strong random value.
- [ ] Debug endpoints disabled in production unless explicitly approved.
- [ ] CSRF protection verified for state-changing endpoints.
- [ ] Session cookie security flags verified in production.
- [ ] Error responses do not leak internal details in production.
- [ ] Request IDs included for traceability.
- [ ] Audit logs recorded for create/update/delete operations.

## Operational Controls

- [ ] Monitoring and alerting ownership assigned.
- [ ] Log retention period approved by policy.
- [ ] Backup/restore tested and evidence captured.
- [ ] Vulnerability patch cadence documented.
- [ ] Deployment rollback procedure validated.

## Evidence Pointers

- Technical readiness: ISO_READINESS_EVIDENCE.md
- SoA starter: ISO_STATEMENT_OF_APPLICABILITY_TEMPLATE.md
- Deployment controls: RAILWAY_DEPLOYMENT_RUNBOOK.md

## Approval

- Prepared by: ______________________ Date: __________
- Reviewed by: ______________________ Date: __________
- Approved by: ______________________ Date: __________
