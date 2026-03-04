# Production Deployment Guide

## Current Status
✅ **Application**: Deployed on Railway  
✅ **URL**: https://takhlees-asset-management-portal.up.railway.app  
✅ **Node Version**: 18.20.8  
✅ **Database**: PostgreSQL (via Railway)  
✅ **Region**: us-east4  

## Recent Production Improvements

### 1. ✅ Session Store (FIXED)
**Problem**: Was using MemoryStore (causes memory leaks, loses sessions on restart)  
**Solution**: Now using PostgreSQL-backed session store (connect-pg-simple)

**Benefits**:
- ✅ Sessions persist across container restarts
- ✅ Memory-efficient (no session leak)
- ✅ Scales with multiple replicas
- ✅ Session table auto-created on startup

### 2. ✅ Email Notifications
**Status**: Implemented and ready  
**Features**:
- Password reset emails with HTML templates
- Professional branded template with Takhlees logo
- 1-hour expiration warning
- Fallback if SMTP fails (error logged, doesn't crash)

**Configuration Required**:
```env
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
```

### 3. ✅ Security Features
- **Password Strength**: 8+ chars, uppercase, lowercase, number, special char
- **Session Security**: httpOnly, secure cookies, sameSite=strict
- **SQL Injection Prevention**: Parameterized queries throughout
- **CSRF Protection**: Session-based tokens
- **Password Reset**: Secure token-based with 1-hour expiry
- **OAuth Support**: Google, Microsoft, GitHub

## Production Checklist

### Environment Variables (Railway Variables Tab)
Add these to Railway's Variables section:

```env
# Database (usually auto-configured by Railway)
DATABASE_URL=postgresql://user:pass@host:port/dbname
PGHOST=...
PGPORT=...
PGUSERNAME=...
PGPASSWORD=...
PGDATABASE=...

# Session Secret (REQUIRED FOR PRODUCTION)
SESSION_SECRET=generate-a-long-random-string-here

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# Application URL (for password reset links)
APP_URL=https://takhlees-asset-management-portal.up.railway.app

# Node Environment
NODE_ENV=production

# (Optional) OAuth Credentials
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
MICROSOFT_CLIENT_ID=...
MICROSOFT_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

### Generate Secure SESSION_SECRET

**Option 1: Use Node.js**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Option 2: Use openssl**
```bash
openssl rand -hex 32
```

Copy the output and paste into Railway Variables as `SESSION_SECRET`.

## Current Deployment Architecture

```
┌─────────────────────────────────────────────┐
│  Browser (User)                             │
└──────────────┬──────────────────────────────┘
               │ HTTPS
               ▼
┌─────────────────────────────────────────────┐
│  Railway Container                          │
│  ├─ Node.js 18.20.8                        │
│  ├─ Express Server (Port 8080)             │
│  ├─ Session Store (PostgreSQL)             │
│  └─ Email Service (Nodemailer)             │
└──────────────┬──────────────────────────────┘
               │ TCP
               ▼
┌─────────────────────────────────────────────┐
│  Railway PostgreSQL                         │
│  ├─ Users Table                            │
│  ├─ Assets Tables (20+ categories)         │
│  └─ Session Table (auto-created)           │
└─────────────────────────────────────────────┘
```

## Monitoring & Troubleshooting

### Viewing Logs
1. Go to Railway Dashboard
2. Click "asset-management" deployment
3. View real-time logs in "Build Logs" or "Deploy Logs"
4. Filter by time range or search for errors

### Common Issues

**❌ "Session not saved"**
- Check `SESSION_SECRET` is set in Variables
- Restart deployment after adding variables
- Check database connection is working

**❌ "Password reset email not sent"**
- Verify EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS
- Check Gmail has 2FA + App Password generated
- Look for error in logs
- Email system fails gracefully (won't crash app)

**❌ "Database connection timeout"**
- Verify DATABASE_URL is correct
- Check PostgreSQL connection pool limits
- Ensure Railway PostgreSQL is running
- Look at Network Flow Logs in Railway

**❌ "High memory usage"**
- Previously: MemoryStore session leak (now fixed)
- Monitor with Railway Metrics tab
- Check for unbounded arrays in code

### Health Check
The app includes a health check endpoint:
```
GET /health
```

Railway should be configured to use this for replica health checks.

## Deployment Process

### Deploy changes from git:
```bash
# Push to your git repository (connected to Railway)
git push origin main

# Railway auto-deploys on push
# Watch logs in Railway Dashboard
```

### Rollback (if needed):
1. Railway Dashboard → Deployments tab
2. Click previous deployment
3. "Redeploy" button
4. App reverts to that version

## Performance Optimization Tips

### 1. Database
- ✅ Connection pooling (already configured)
- ✅ Parameterized queries (prevents SQL injection + faster)
- ⏳ Add indexes to frequently filtered columns

### 2. Caching
- ⏳ Could add Redis for session caching
- ⏳ Cache static QR codes/barcodes
- ⏳ Browser caching headers for CSS/JS

### 3. Scaling
- **Current**: 1 Replica (add more if traffic grows)
- **Session**: ✅ Works with multiple replicas (PostgreSQL store)
- **Sticky Sessions**: Not needed (sessions are in DB, not memory)

## Security Hardening (Advanced)

### Already Implemented
✅ HTTPS (Railway auto-generates certificates)  
✅ Secure session cookies (httpOnly, sameSite, secure)  
✅ CORS configured  
✅ SQL injection prevention  
✅ Password hashing (bcrypt 10 rounds)  

### Recommended for Production
- [ ] Add rate limiting (express-rate-limit)
- [ ] Add request logging/monitoring (winston, morgan)
- [ ] Add vulnerability scanning in CI/CD
- [ ] Enable two-factor authentication
- [ ] Add API key authentication for external integrations
- [ ] Set up automated backups for PostgreSQL

## Cost Optimization

### Railway Pricing
- **Compute**: ~$5/month for 1 GB / 1 vCPU
- **PostgreSQL**: ~$15/month for 1 GB database
- **Build**: Included in plan
- **Network**: Included for Railway services

**Estimated**: $20-30/month for current setup

### Cost Reduction Options
- Scale down vCPU during off-hours (if traffic is low)
- Archive old asset records to save DB space
- Optimize images/PDFs for size

## Backup Strategy

### PostgreSQL Automatic Backups
Railway PostgreSQL includes automatic backups:
1. Railway Dashboard → PostgreSQL plugin
2. "Backups" tab shows history
3. Can restore from any previous backup

### Manual Backup
```bash
# Export database
pg_dump $DATABASE_URL > backup.sql

# Restore database
psql $DATABASE_URL < backup.sql
```

## Next Steps

1. ✅ **Session Store**: Fixed (connected to PostgreSQL)
2. ✅ **Email**: Configured (add credentials to Railway Variables)
3. ⏸️ **Rate Limiting**: Optional - add if you see abuse
4. ⏸️ **Monitoring**: Optional - set up error tracking (Sentry)
5. ⏸️ **Backup**: Railway auto-handles, consider scheduling exports

## Support Resources

- **Railway Docs**: https://docs.railway.app
- **Express.js Docs**: https://expressjs.com
- **PostgreSQL Docs**: https://www.postgresql.org/docs/
- **Node.js Docs**: https://nodejs.org/docs/

## Deployment Timeline

| Date | Event | Status |
|------|-------|--------|
| Mar 4, 2026 | Initial deployment | ✅ Active |
| Mar 4, 2026 | Session store migration | ✅ Complete |
| - | Email configuration | ⏳ Awaiting |
| - | OAuth setup (optional) | ⏳ Awaiting |

---

**Last Updated**: March 4, 2026  
**Environment**: Production (us-east4)  
**Node Version**: 18.20.8  
**Status**: ✅ Running
