# Access Control Policy

## Policy Statement

Access to the asset management system is granted on least privilege and role-based need-to-know principles.

## Roles

- Admin: Full access including privileged user management and destructive operations.
- User: Standard operational access based on assigned permissions.
- Guest: Restricted visibility and no privileged operations.

## Mandatory Controls

1. All privileged endpoints require authenticated sessions and admin authorization.
2. Session cookies must be `httpOnly`, `secure` in production, and same-site protected.
3. Account lifecycle must support timely provisioning and deprovisioning.
4. Shared accounts are prohibited.
5. Passwords must meet minimum complexity and storage requirements.

## Access Review

- Privileged access review cadence: monthly.
- Dormant accounts older than 90 days: disable pending review.

## Exceptions

Any exception requires documented business justification, owner approval, and expiration date.
