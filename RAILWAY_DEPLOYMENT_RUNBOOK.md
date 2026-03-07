# Railway Deployment Runbook

## Purpose

This runbook is the operational checklist for releasing Takhlees Asset Management System to Railway with production-safe defaults.

## 1) Release Gate (Mandatory)

Run this from the project root before every production deployment:

```bash
npm run release:check
```

This command enforces:

- Strict environment validation (`preflight:strict`)
- Full automated test suite (`npm test`)

Do not deploy if this command fails.

---

## 2) Environment Variable Matrix

### Required (Production)

| Variable | Required | Example | Notes |
|---|---|---|---|
| `NODE_ENV` | Yes | `production` | Enables production security behavior |
| `SESSION_SECRET` | Yes | `64+ random chars` | Must be strong; weak/missing fails startup |
| `CORS_ORIGINS` | Yes | `https://assets.example.gov.ae` | Comma-separated allowed browser origins |
| `DATABASE_URL` | Yes* | `postgresql://...` | Preferred on Railway |

> *You may alternatively use full `PG*` set (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`).

### Recommended (Production)

| Variable | Example | Notes |
|---|---|---|
| `PORT` | `3000` | Railway usually injects this automatically |
| `SESSION_COOKIE_NAME` | `takhlees.sid` | Defaults safely if omitted |
| `SESSION_COOKIE_DOMAIN` | `.example.gov.ae` | Optional; set only if needed |
| `DB_SSL_REJECT_UNAUTHORIZED` | `false` or `true` | Depends on DB cert policy |
| `LOG_LEVEL` | `info` | Use `warn`/`error` for lower verbosity |

### Optional Features

| Variable Group | Needed For |
|---|---|
| `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USER`, `EMAIL_PASS` | Password reset email flow |
| `GOOGLE_*` / `MICROSOFT_*` / `GITHUB_*` | OAuth providers |

If OAuth variables are not configured, do not expose OAuth login buttons in production UI.

---

## 3) Railway Configuration Expectations

- Build/runtime:
  - `nixpacks.toml` pins Node 18 (`nodejs_18`)
  - Start command: `node server.js`
- Process type:
  - `Procfile` uses `web: node server.js`
- App health endpoint:
  - `GET /api/health` (includes DB connectivity check)

---

## 4) Pre-Deploy Checklist

- [ ] `npm ci` completes successfully
- [ ] `npm run release:check` passes
- [ ] Database migrations are applied (`npm run migrate`)
- [ ] Railway production variables are configured
- [ ] `SESSION_SECRET` rotated and not reused from non-prod
- [ ] `CORS_ORIGINS` contains only approved domains
- [ ] OAuth callback URLs match production domain (if OAuth enabled)
- [ ] `GET /api/health` returns `200` with `database: connected`

---

## 5) Deploy Procedure (Railway)

1. Push changes to deployment branch.
2. Confirm Railway service has required env vars.
3. Trigger deploy.
4. Verify startup logs show no `[ENV ERROR]`.
5. Run smoke checks:
   - `GET /api/health`
   - login flow
   - create/read/delete asset flow
   - history page load
6. Validate CSRF-protected actions (`POST/PUT/DELETE`) from UI.

---

## 6) Post-Deploy Verification

- Authentication:
  - Session login/logout works
  - Admin-only endpoints return `403` for non-admin users
- Asset operations:
  - Create/update/delete work for valid roles
  - Invalid category/id is rejected safely
- Security:
  - Helmet headers present
  - CSRF protection active
  - Rate limiting active
- Observability:
  - Logs rotate under `logs/`
  - No secrets/tokens appear in logs (redaction enabled)

---

## 7) Rollback Plan

If deployment fails health or critical smoke checks:

1. Roll back to the previous Railway deployment.
2. Restore previous env variables (if changed).
3. Verify `GET /api/health` is green.
4. Open incident note with root cause and corrective action.

---

## 8) Emergency Commands

```bash
# Strict environment validation
npm run preflight:strict

# Run full test suite
npm test

# Check migration status
npm run migrate:status

# Roll back last migration batch
npm run migrate:rollback
```
