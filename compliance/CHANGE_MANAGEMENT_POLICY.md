# Change Management Policy

## Objective

Ensure all production-impacting changes are planned, reviewed, tested, approved, and traceable.

## Change Categories

- Standard: Low-risk, pre-approved routine changes.
- Normal: Planned changes requiring review and approval.
- Emergency: Urgent changes for incident containment/recovery.

## Mandatory Requirements

1. Every change must reference a ticket or work item.
2. Release gate must pass before deployment:
   - strict preflight
   - automated tests
   - docs lint
   - compliance check
3. Security-impacting changes require security review.
4. Rollback strategy must be documented before release.
5. Post-deploy verification must be completed and recorded.

## Emergency Change Process

1. Incident Commander authorizes emergency action.
2. Minimum peer review performed where feasible.
3. Immediate post-change validation performed.
4. Retrospective and formal documentation completed within 1 business day.

## Change Record Fields

- Change ID
- Requester
- Risk level
- Approval
- Deployment window
- Validation evidence
- Rollback result
