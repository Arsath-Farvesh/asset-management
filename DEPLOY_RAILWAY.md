Railway deployment notes for QR Asset Management

This repo is ready to deploy on Railway. The server already reads `process.env.PORT` and supports a `DATABASE_URL` connection string.

Quick checklist (Railway)
- Ensure `package.json` has a `start` script. This project contains: `"start": "node server.js"`.
- Add a PostgreSQL plugin on Railway (or create a database). Railway will provide a `DATABASE_URL` env var.
- Add these environment variables in Railway (Project > Variables):
  - `DATABASE_URL` (set automatically by the Postgres plugin) OR set `DB_USER`, `DB_HOST`, `DB_NAME`, `DB_PASSWORD`, `DB_PORT` manually if you prefer.
  - `SESSION_SECRET` (required)
  - `EMAIL_USER` and `EMAIL_PASS` (if you need password reset emails)
  - `RESET_TOKEN_EXPIRY` (optional, milliseconds)
  - `FRONTEND_URL` (optional — used for CORS; defaults to `http://localhost:5173` locally)

Deployment steps (recommended)
1. Push your repo to GitHub and connect the GitHub repository from Railway.
2. In Railway, create a new project and choose "Deploy from GitHub" (or use the CLI `railway up`).
3. Add the PostgreSQL plugin; note the `DATABASE_URL` value that Railway sets automatically.
4. Set the required environment variables in Railway (see checklist above).
5. Deploy. Railway will run `npm install` then `npm start`.

Tips & caveats
- The server uses `connectionString: process.env.DATABASE_URL` and sets `ssl` when `NODE_ENV === 'production'`. Railway Postgres requires SSL; the code sets `rejectUnauthorized: false` which is compatible with Railway.
- If you prefer to use individual DB env vars (`DB_USER`, etc.), add them in Railway and the server will still work because `DATABASE_URL` is optional.
- Ensure `SESSION_SECRET` is set to a long random value in production.
- Update `FRONTEND_URL` to your hosted frontend origin (or set CORS origin accordingly).
- For email sending in production, replace Gmail credentials or use a transactional email provider.

Railway CLI quick deploy (local)
```powershell
npm install -g railway
railway login
railway link
railway up
```

If you'd like, I can also:
- Add a `Procfile` (not required) or a `railway.json` with build settings;
- Create a small `deploy-checklist.md` describing checks to perform after first deploy (DB seed, CORS, email).
