# Risk Register

## Method

Use this register to track project risks, risk owners, treatment plans, and target closure dates.

## Scale

- Likelihood: 1 (Low) to 5 (High)
- Impact: 1 (Low) to 5 (High)
- Risk Score = Likelihood x Impact

## Register

| ID | Risk Description | Likelihood | Impact | Score | Treatment | Owner | Due Date | Status |
|---|---|---:|---:|---:|---|---|---|---|
| R-001 | Misconfigured production CORS could expose APIs to unapproved browser origins. | 2 | 4 | 8 | Enforce fail-closed behavior and deployment validation. | Security Lead | 2026-03-31 | Mitigated |
| R-002 | Insufficient test depth for privileged flows may hide regressions. | 3 | 3 | 9 | Expand integration tests for role and control paths. | Engineering Lead | 2026-04-15 | Open |
| R-003 | CSP inline allowances could increase XSS impact. | 3 | 4 | 12 | Stage strict CSP in report-only, then enforce. | AppSec Owner | 2026-04-30 | In Progress |
| R-004 | Audit evidence incomplete if process records are missing. | 3 | 4 | 12 | Maintain SoA, IR, BCP, and change records. | ISMS Owner | 2026-04-30 | In Progress |
| R-005 | Log retention not formally approved may conflict with compliance obligations. | 2 | 3 | 6 | Define retention policy and enforcement checks. | Operations Lead | 2026-04-10 | Open |

## Review Log

| Date | Reviewer | Summary |
|---|---|---|
| 2026-03-13 | Project Team | Initial risk baseline created. |
