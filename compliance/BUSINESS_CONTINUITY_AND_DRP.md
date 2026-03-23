# Business Continuity and Disaster Recovery Plan

## Objective

Ensure critical asset management services can be restored within approved recovery targets after major disruption.

## Recovery Targets

- RTO (Recovery Time Objective): 4 hours
- RPO (Recovery Point Objective): 1 hour

## Critical Services

- Authentication and authorization APIs
- Asset CRUD endpoints
- Audit log persistence
- Database availability

## Backup Strategy

- Database backups: hourly snapshots, daily full backups.
- Retention: minimum 30 days unless stricter legal requirements apply.
- Backup storage: encrypted at rest and access restricted.

## Recovery Procedure

1. Declare disaster and activate incident command.
2. Restore database to latest validated recovery point.
3. Redeploy service from approved release artifact.
4. Run migrations if required and verify schema consistency.
5. Execute smoke tests for auth, assets, and audit logging.
6. Communicate recovery completion to stakeholders.

## Testing Cadence

- Tabletop continuity exercise: quarterly.
- Full restore drill: at least twice per year.

## Evidence

- Store recovery test records in change management repository.
- Record any RTO/RPO deviation and corrective actions.
