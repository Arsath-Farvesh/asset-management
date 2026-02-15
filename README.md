# Asset Management (QR-based)

Simple asset management demo with QR and barcode generation.

## Features
- Express server with static frontend in `public/`
- Dynamic asset categories and simple APIs (requires Postgres)
- QR code and barcode generation

## Prerequisites
- Node.js 18.x (recommended)
- npm
- PostgreSQL (optional — required for full functionality)

## Quick start
1. Install dependencies

```bash
npm install
```

2. Create a `.env` file (see example below)

3. Start the app

```bash
npm start
```

4. Open `http://localhost:3000` (or the `PORT` you set)

## Environment variables
Create a `.env` file in the project root with these values as needed:

```text
PORT=3000
NODE_ENV=development
DATABASE_URL=postgres://user:password@host:5432/database
SESSION_SECRET=change_this
EMAIL_USER=youremail@example.com
EMAIL_PASS=your-email-password
RESET_TOKEN_EXPIRY=3600
FRONTEND_URL=http://localhost:3000
```

Notes:
- If `DATABASE_URL` is not provided, the server will start but many API endpoints that require the database will return errors. This repository includes a guard so the server can run for frontend testing without a DB.
- For production Postgres providers that require SSL, ensure your `DATABASE_URL` and `NODE_ENV=production` are configured correctly. The server sets `ssl: { rejectUnauthorized: false }` when `NODE_ENV` is `production`.

## Running with a local Postgres (example)
Start Postgres locally, then set `DATABASE_URL` and run:

Windows PowerShell:

```powershell
$env:DATABASE_URL = "postgres://user:password@localhost:5432/asset_db"
npm start
```

Linux / macOS:

```bash
export DATABASE_URL="postgres://user:password@localhost:5432/asset_db"
npm start
```

## Database behavior
- The server attempts to create tables and triggers automatically when a valid `DATABASE_URL` is provided.
- Default users are created automatically on startup (only when DB is configured).

## Contributing
- Create a branch: `git checkout -b feat/my-change`
- Commit changes: `git commit -am "feat: ..."`
- Push and open a PR

## Troubleshooting
- If you see errors about SSL or authentication when connecting to Postgres, check your provider docs and connection string. For some hosted providers you may need to include `?sslmode=require` or configure SSL settings.
- If the server starts but APIs return `No DATABASE_URL set`, provide a valid `DATABASE_URL`.

## License
MIT
