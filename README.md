# Takhlees Asset Management System

A professional asset tracking and management solution for government services in Dubai.

## 🚀 Features

- Multi-category Asset Management (20+ categories)
- QR Code & Barcode Generation
- User Authentication with role-based access control
- OAuth Support (Google, Microsoft, GitHub)
- Password Reset via email
- Asset History Tracking
- PDF Export functionality
- Responsive professional UI
- Security: Helmet headers, rate limiting, input validation
- Professional Logging with Winston

## 🔧 Quick Start

```bash
npm install
cp .env .env.local
# Edit .env.local with your settings
npm start
```

## 🔐 Default Users

| Username | Password | Role |
|----------|----------|------|
| admin | TakhleeAdmin@2024! | Admin |
| user1 | TakhleeUser@2024! | User |

**⚠️ Change passwords in production!**

## 🛡️ Security Features (NEW - March 2026)

- ✅ Helmet.js security headers
- ✅ Rate limiting (API: 100/15min, Auth: 5/15min)
- ✅ Input validation (express-validator)
- ✅ Winston logging with daily rotation
- ✅ Debug mode disabled in production
- ✅ Removed unused dependencies (15MB saved)

## 📄 License

ISC License

## 👨‍💻 Authors

Arsath Farvesh, Shahul
