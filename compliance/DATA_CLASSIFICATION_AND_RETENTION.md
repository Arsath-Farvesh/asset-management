# Data Classification and Retention

## Classification Levels

- Public: Information approved for external disclosure.
- Internal: Non-public operational information.
- Confidential: Sensitive business data requiring restricted access.
- Restricted: Highly sensitive data requiring strict controls and auditing.

## Typical Data Mapping

| Data Type | Classification | Notes |
|---|---|---|
| API docs and generic UI text | Public | No sensitive details included. |
| Asset metadata (non-sensitive fields) | Internal | Access by authenticated users only. |
| User profile fields and role data | Confidential | Restricted to operational need. |
| Credentials, session secrets, reset tokens | Restricted | Never logged or committed. |

## Retention Baseline

- Application logs: minimum 30 days, extend per legal requirement.
- Audit logs: minimum 1 year for traceability where legally permissible.
- Incident records: minimum 2 years.
- Backups: 30 days baseline, adjust by policy/regulation.

## Deletion and Disposal

- Use approved deletion workflows and maintain deletion evidence for restricted data.
- Ensure backup expiration and disposal follow the same classification requirements.
