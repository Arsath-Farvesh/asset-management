# Incident Response Runbook

## Objective

Provide a repeatable process to detect, contain, eradicate, recover, and report security incidents affecting the asset management system.

## Severity Levels

- Sev-1: Confirmed data breach, active compromise, or complete outage.
- Sev-2: Suspected compromise, partial outage, or critical control failure.
- Sev-3: Low-impact security event with no confirmed compromise.

## Roles

- Incident Commander: Coordinates response and decisions.
- Technical Lead: Executes technical containment and recovery.
- Communications Lead: Manages stakeholder and customer communications.
- Compliance Lead: Tracks legal/regulatory notification obligations.

## Response Workflow

1. Detect and triage.
2. Classify severity.
3. Contain impact (revoke sessions, disable affected endpoints, block indicators).
4. Preserve evidence (logs, request IDs, DB snapshots, deployment metadata).
5. Eradicate root cause.
6. Recover service and validate controls.
7. Document incident report and corrective actions.

## Immediate Containment Playbook

1. Rotate `SESSION_SECRET` and invalidate active sessions for auth compromise events.
2. Restrict ingress/CORS and disable optional debug endpoints.
3. Roll back to last known good deployment if required.
4. Enable heightened logging level for investigation.

## Evidence Collection Checklist

- [ ] Incident timeline with UTC timestamps.
- [ ] Request IDs and endpoint traces.
- [ ] Relevant log extracts with integrity preservation.
- [ ] Database and migration state snapshot.
- [ ] Deployed commit hash and environment details.

## Post-Incident Requirements

- Root cause analysis completed within 5 business days.
- Corrective actions created, owned, and tracked.
- Risk register updated.
- Lessons learned reviewed in management meeting.
