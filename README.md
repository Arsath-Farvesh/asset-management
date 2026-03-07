# Takhlees Asset Management System

A professional enterprise-grade asset tracking and management solution
for government services in Dubai.

## 🚀 Features

### Core Functionality

- **Multi-category Asset Management** - Keys, Laptops, Monitors,
  Accessories, ID Cards
- **QR Code & Barcode Generation** - Instant asset identification
- **Asset History Tracking** - Complete audit trail
- **PDF Export** - Professional reporting
- **Responsive UI** - Bootstrap 5 professional theme

### Authentication & Authorization

- **Session-based Authentication** - Secure login system
- **OAuth 2.0 Support** - Google, Microsoft, GitHub integration
- **Role-based Access Control** - User/Admin permissions
- **Password Reset** - Email-based recovery flow
- **CSRF Protection** - Token-based security

### Security (Enterprise Grade)

- ✅ **Helmet.js** - Security headers (XSS, clickjacking protection)
- ✅ **Rate Limiting** - API: 100/15min, Auth: 5/15min
- ✅ **Input Sanitization** - XSS prevention middleware
- ✅ **CSRF Protection** - csurf middleware with token validation
- ✅ **Compression** - Gzip compression (60-80% bandwidth reduction)
- ✅ **Session Security** - PostgreSQL session store with expiry
- ✅ **Password Hashing** - Bcrypt (10 rounds)

### Performance & Monitoring

- ✅ **Winston Logging** - Daily rotating file logs (error/combined)
- ✅ **Database Pooling** - Connection pool (max 20)
- ✅ **Indexed Queries** - Strategic database indexing
- ✅ **Health Checks** - `/api/health` endpoint

## 📁 Project Structure

```text
asset-management/
├── public/              # Frontend HTML/CSS/JS
├── src/
│   ├── config/          # Database, logger, passport, swagger
│   ├── middleware/      # Auth, security, rate limiting
│   ├── services/        # Business logic layer
│   ├── controllers/     # Request handlers
│   └── routes/          # API route definitions
├── migrations/          # Knex database migrations
├── __tests__/           # Jest unit & integration tests
├── server.js            # Application entry point (123 lines)
├── knexfile.js          # Database migration config
├── jest.config.js       # Test configuration
└── DATABASE_SCHEMA.md   # Complete schema documentation
```

## 🏗️ Architecture

### Modular MVC Pattern

- **91% code reduction** - Server.js: 1,412 → 123 lines
- **Separation of Concerns** - Config, middleware, services, controllers, routes
- **Testable Code** - Unit & integration test coverage
- **Maintainable** - Clear module boundaries

### Technology Stack

- **Runtime**: Node.js 18.x
- **Framework**: Express.js 4.21.2
- **Database**: PostgreSQL (pg 8.16.3)
- **Authentication**: Passport.js 0.7.0
- **Security**: helmet 8.1.0, csurf 1.11.0, bcrypt 6.0.0
- **Logging**: winston 3.11.0
- **Testing**: Jest + Supertest
- **Migrations**: Knex.js
- **API Docs**: Swagger (OpenAPI 3.0)

## 🔧 Quick Start

### Prerequisites

- Node.js 18.x or higher
- PostgreSQL 12+
- SMTP server (for email features)

### Installation

```bash
# Clone repository
git clone <repository-url>
cd asset-management

# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Edit .env with your database and SMTP settings
nano .env

# Run database migrations
npm run migrate

# Start server
npm start
```

### Development Mode

```bash
# Start with nodemon (auto-reload)
npm run dev

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run only unit tests
npm run test:unit

# Run only integration tests
npm run test:integration

# Run environment preflight checks
npm run preflight

# Run strict release gate (preflight + tests)
npm run release:check
```

### Deployment Preflight (Recommended)

Before production deployment, run strict validation:

```bash
npm run preflight:strict
```

This validates required environment configuration and blocks deployment on invalid settings.

For complete Railway deployment procedure and production variable matrix,
see [RAILWAY_DEPLOYMENT_RUNBOOK.md](RAILWAY_DEPLOYMENT_RUNBOOK.md).

## 🔐 Default Users

| Username | Password            | Role  | Permissions          |
| :------- | :------------------ | :---- | :------------------- |
| admin    | TakhleeAdmin@2024!  | Admin | Full access          |
| user1    | TakhleeUser@2024!   | User  | View, Create, Delete |

**⚠️ CRITICAL: Change all default passwords before production deployment!**

## 📊 API Documentation

### Interactive API Explorer

Visit `/api-docs` after starting the server for interactive API
documentation powered by Swagger UI.

### Key Endpoints

#### Authentication

- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout  
- `GET /api/auth/me` - Get current user profile
- `GET /api/auth/users` - List all users (Admin only)
- `PUT /api/auth/user/profile` - Update profile

#### Assets

- `GET /api/assets/:category` - List assets by category
- `POST /api/assets/:category` - Create new asset (requires CSRF token)
- `GET /api/assets/:category/:id` - Get single asset
- `PUT /api/assets/:category/:id` - Update asset (Admin only)
- `DELETE /api/assets/:category/:id` - Delete asset
- `POST /api/assets/bulk-delete` - Bulk delete assets

#### Health

- `GET /api/health` - System health check
- `GET /api/csrf-token` - Get CSRF token for forms

### CSRF Token Usage

All `POST`, `PUT`, `DELETE` requests require a CSRF token:

```javascript
// 1. Get CSRF token
const response = await fetch('/api/csrf-token');
const { csrfToken } = await response.json();

// 2. Include in request headers
await fetch('/api/assets/keys', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'CSRF-Token': csrfToken
  },
  body: JSON.stringify(data)
});
```

## 🗄️ Database

### Schema Documentation

See [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) for complete schema documentation.

### Migrations

```bash
# Run pending migrations
npm run migrate

# Rollback last batch
npm run migrate:rollback

# Check current version
npm run migrate:status
```

### Key Tables

- `users` - User accounts
- `keys`, `laptops`, `monitors`, `accessories`, `id_cards` - Asset categories
- `audit_logs` - Change tracking
- `session` - Express sessions

## 🧪 Testing

### Test Coverage

- **Unit Tests**: Service layer (authService, assetService)
- **Integration Tests**: API endpoints
- **Current Coverage**: 46.64% (targeting 70%+)

```bash
# Run all tests with coverage
npm test

# Watch mode for development
npm run test:watch

# Unit tests only
npm run test:unit

# Integration tests only
npm run test:integration
```

### Test Structure

```text
__tests__/
├── unit/
│   ├── authService.test.js
│   └── assetService.test.js
└── integration/
    ├── auth.routes.test.js
    └── assets.routes.test.js
```

## 📈 Recent Improvements (March 2026)

### Phase 1: Security Hardening ✅

- CSRF protection with csurf middleware
- Input sanitization (XSS prevention)
- Gzip compression (60-80% bandwidth savings)
- Security dependencies resolved

### Phase 2: Architecture Refactoring ✅

- Modular MVC structure (17 new modules)
- Server.js reduced 91% (1,412 → 123 lines)
- Separated concerns (config, middleware, services, controllers, routes)
- 100% backward compatibility maintained

### Phase 3: Testing Framework ✅

- Jest + Supertest installed
- Unit tests for service layer (9 passing)
- Integration tests for API routes
- Code coverage reporting

### Phase 4: Database Optimization ✅

- Knex.js migration system
- Strategic indexing (location, employee_name, asset_tag, case_name)
- Audit logs table for change tracking
- Complete schema documentation

### Phase 5: Documentation & API Specs ✅

- Swagger/OpenAPI 3.0 specification
- Interactive API explorer at `/api-docs`
- JSDoc comments on all routes
- DATABASE_SCHEMA.md documentation

## 🔒 Security Best Practices

### Production Checklist

- [ ] Change all default passwords
- [ ] Set `NODE_ENV=production`
- [ ] Enable PostgreSQL SSL (`PGSSLMODE=require`)
- [ ] Configure firewall rules
- [ ] Set strong `SESSION_SECRET`
- [ ] Configure SMTP with TLS
- [ ] Set up automated backups
- [ ] Enable access logs review
- [ ] Configure rate limiting thresholds
- [ ] Review CSP directives in helmet config

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname
PGHOST=localhost
PGPORT=5432
PGUSER=postgres
PGPASSWORD=yourpassword
PGDATABASE=asset_management

# Server
PORT=3000
NODE_ENV=production
SESSION_SECRET=your-super-secret-session-key

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# OAuth (optional)
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
MICROSOFT_CLIENT_ID=...
MICROSOFT_CLIENT_SECRET=...
```

## 📊 Performance Metrics

- **Response Time**: <100ms (average)
- **Compression**: 60-80% reduction with gzip
- **Database Queries**: Optimized with indexes
- **Concurrent Users**: Supports 100+ simultaneous connections
- **Session Storage**: PostgreSQL-backed (persistent)

## 🐛 Troubleshooting

### Common Issues

#### Database Connection Failed

```bash
# Check PostgreSQL is running
pg_isready

# Verify credentials in .env
echo $DATABASE_URL
```

#### CSRF Token Invalid

- Ensure cookies are enabled
- Check session is active before getting token
- Verify token is sent in `CSRF-Token` header

#### Tests Failing

```bash
# Clean install dependencies
rm -rf node_modules package-lock.json
npm install

# Run with verbose output
npm test -- --verbose
```

## 📄 License

ISC License - see LICENSE file for details

## 👨‍💻 Maintenance & Support

### Logging

Logs are stored in the project root:

- `error.log` - Error-level logs only
- `combined.log` - All logs (info, warn, error)
- Rotates daily with 14-day retention

### Monitoring

- Health check: `GET /api/health`
- Session count: Query `session` table
- Error tracking: Review `error.log`
- Audit trail: Query `audit_logs` table

---

Built with ❤️ for government services in Dubai.

Arsath Farvesh, Shahul
