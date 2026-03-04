# Railway Production Setup Checklist

Complete these steps to fully configure your production deployment:

## Step 1: Set SESSION_SECRET ⚙️

**Why**: Secure session encryption. Different value per environment.

1. Open Terminal:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

2. Copy the output (long hex string)

3. Go to Railway Dashboard:
   - Click "asset-management" 
   - Click "Variables" tab
   - Click "New Variable"
   - Name: `SESSION_SECRET`
   - Value: Paste the hex string from step 2
   - Click "Add"

4. Restart deployment:
   - Go back to "Deployments" tab
   - Click the active deployment
   - Scroll down, click "Restart Deployment"
   - Wait for it to restart (2-3 minutes)

✅ Check: No more "MemoryStore" warning in logs

## Step 2: Configure Email (Optional but Recommended) 📧

For password reset emails to work:

1. Get Gmail App Password:
   - Go to https://myaccount.google.com/security
   - Enable 2-Step Verification (if not done)
   - Find "App passwords"
   - Select: Mail + Your Device
   - Click "Generate"
   - Copy the 16-character password

2. Add to Railway Variables:
   - `EMAIL_HOST` = `smtp.gmail.com`
   - `EMAIL_PORT` = `587`
   - `EMAIL_USER` = your-gmail@gmail.com
   - `EMAIL_PASS` = (16-char password from step 1)

3. Restart deployment

✅ Check: Try password reset, should receive email

## Step 3: Test Your Deployment 🧪

1. **Test Production URL**:
   - https://takhlees-asset-management-portal.up.railway.app
   - Should load the login page

2. **Test Login**:
   - Username: `admin`
   - Password: `TakhleeAdmin@2024!`
   - Should successfully log in

3. **Test Session Persistence** (NEW):
   - Log in
   - Restart deployment from Railway
   - Refresh page
   - Should still be logged in (sessions now persistent!)

4. **Test Email** (Optional):
   - Click "Forgot Password"
   - Enter email: `arsathfarvesh02@gmail.com`
   - Check inbox for reset email
   - Click reset link and change password

## Step 4: Monitor Production 📊

### View Real-Time Logs
1. Railway Dashboard → asset-management
2. "Build Logs" tab shows startup
3. Scroll to see requests coming in
4. Filter by timestamp or search for errors

### Key Health Metrics
- **Memory**: Should be stable (not increasing)
- **CPU**: Should be under 50% on idle
- **Database**: "PostgreSQL connected" message

### Common Log Messages to Expect
```
✅ PostgreSQL connected
✅ Database connection verified
✅ Users table ready
✅ Session table ready (NEW!)
✅ Default users created
🚀 Server running on port 8080
2026-03-04T... GET /health
```

## Step 5: Configure Auto-Restart (Recommended) 🔄

To automatically restart deployments if they crash:

1. Railway Dashboard → asset-management
2. Settings tab
3. Look for "Restart Policy" or "Auto-restart"
4. Enable if available

## Step 6: Set Up Monitoring Alerts (Advanced)

Monitor for issues:

1. **High Memory**: Logs MemoryStore warning (should be GONE now)
2. **Database Errors**: Look for "connection error"
3. **Email Failures**: Look for "Failed to send reset email"
4. **Session Errors**: Look for "Session store error"

## Database Sessions Check

To verify PostgreSQL session store is working:

In Railway PostgreSQL shell:
```sql
-- Connect to your database, then:
SELECT COUNT(*) FROM session;
```

Should show session records (grows with active users).

## Verify Fixes Applied

Run this in Terminal to see changes:
```bash
grep -n "pgSession\|connect-pg-simple" server.js
```

Should show:
- Line with `connect-pg-simple` import
- Line with `pgSession` store configuration
- No more "MemoryStore" warnings

## What's Fixed in This Update

| Issue | Status | Solution |
|-------|--------|----------|
| MemoryStore leak | ✅ FIXED | PostgreSQL session store |
| Sessions lost on restart | ✅ FIXED | Database persistence |
| Multiple replicas fail | ✅ FIXED | Shared DB store |
| Memory growth | ✅ FIXED | No in-memory storage |

## Next Production Steps (Future)

- [ ] Add rate limiting (if you get DDoS concerns)
- [ ] Set up logging service (Sentry, DataDog)
- [ ] Add database backups (Railway does auto)
- [ ] Configure OAuth providers (optional)
- [ ] Set up custom domain (instead of railway.app)
- [ ] Add CDN for static files (CloudFlare)

## Support

If you encounter issues:

1. **Check logs**: Railway Dashboard → Deployments → Deploy Logs
2. **Check variables**: Make sure SESSION_SECRET is set
3. **Restart**: Try redeploying the app
4. **Rollback**: Go to previous deployment if needed

## Deployment Status

```
🚀 Current: https://takhlees-asset-management-portal.up.railway.app
✅ Status: Active
✅ Node: 18.20.8
✅ Session Store: PostgreSQL (FIXED)
⏳ Email: Ready (awaiting config)
⏳ OAuth: Ready (optional setup)
```

---

**Time to Complete**: 5-10 minutes  
**Difficulty**: Easy  
**Required**: SESSION_SECRET  
**Optional**: Email config  

**Once complete, your production deployment will be fully optimized for scalability and reliability!** 🎉
