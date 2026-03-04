# Email Configuration Setup Guide

## Overview
The password reset feature now sends actual emails to users' inboxes. To enable this, you need to configure email credentials in your `.env` file.

## Gmail Setup (Recommended for Development)

### Step 1: Enable 2-Factor Authentication
1. Go to your Google Account: https://myaccount.google.com/
2. Click **Security** in the left menu
3. Scroll to "How you sign in to Google"
4. Enable **2-Step Verification** (if not already enabled)

### Step 2: Create an App Password
1. Go back to Google Account Security: https://myaccount.google.com/security
2. Look for **"App passwords"** section (only appears if 2FA is enabled)
3. Select:
   - App: **Mail**
   - Device: **Windows Computer** (or your device type)
4. Click **Generate**
5. Copy the 16-character password that appears

### Step 3: Update Your .env File
```env
# Email Configuration (Gmail)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=xxxx xxxx xxxx xxxx
```

Replace:
- `your-email@gmail.com` with your Gmail address
- `xxxx xxxx xxxx xxxx` with the 16-character app password (spaces and all)

### Step 4: Set Application URL (Optional)
For production, add:
```env
APP_URL=https://your-domain.com
```

This ensures reset links point to your live domain instead of localhost.

## Testing Email Configuration

After setting up your `.env` file:

1. Restart the server:
```bash
npm start
```

2. Go to forgot-password.html:
```
http://localhost:3000/forgot-password.html
```

3. Enter an email address for a user (e.g., "arsathfarvesh02@gmail.com" for admin)

4. Check the email inbox - you should receive the reset link within 10 seconds

5. Click the reset link and set a new password

### Troubleshooting

**❌ "Error: Invalid login" or "Authentication failed"**
- Verify the app password is correct (spaces included)
- Check that 2-Step Verification is enabled
- Gmail app passwords are case-sensitive

**❌ "Timeout" or "No response from server"**
- Verify EMAIL_HOST and EMAIL_PORT are correct
- Check your firewall/antivirus isn't blocking SMTP port 587
- Try EMAIL_PORT=465 with secure: true if 587 doesn't work

**❌ Email not arriving**
- Check spam/junk folder
- Verify recipient email address is correct
- Check server console for error messages (npm start output)
- Ensure .env file is in the root directory

**❌ Users don't see verification in email**
- This is normal - the system hides whether an email exists (security feature)
- Check your email provider's log to confirm it was sent

## Production Email Setup

For production use, consider these email providers:

### SendGrid
```env
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USER=apikey
EMAIL_PASS=SG.xxxxxxxxxxxxx
```

### AWS SES (Simple Email Service)
```env
EMAIL_HOST=email-smtp.us-east-1.amazonaws.com
EMAIL_PORT=587
EMAIL_USER=your-ses-username
EMAIL_PASS=your-ses-password
```

### Microsoft Office 365
```env
EMAIL_HOST=smtp.office365.com
EMAIL_PORT=587
EMAIL_USER=your-email@company.com
EMAIL_PASS=your-password
```

## Email Reset Flow

When a user requests password reset:

1. User enters email on forgot-password.html
2. System generates secure reset token (32 random bytes)
3. Reset token is hashed and stored in database (expires in 1 hour)
4. Beautiful HTML email is sent to user's inbox with:
   - Reset link button
   - Reset link URL
   - Security warning about link expiration
   - Branded header with Takhlees logo
5. User clicks reset link and sets new password
6. Reset token is invalidated

## Security Features

✅ **Token Expiration**: Reset links expire after 1 hour
✅ **Token Hashing**: Tokens stored as hashes, not plaintext
✅ **Secure Generation**: Uses cryptographic random bytes
✅ **Email Privacy**: System doesn't reveal if email exists
✅ **HTTPS Recommended**: Reset links should be sent over HTTPS in production
✅ **Password Strength**: New passwords must meet strength requirements

## Email Template

The email sent includes:
- Takhlees branding header with gradient background
- User's username
- Clear reset button
- Backup link URL
- 1-hour expiration warning
- Professional footer

Example email structure:
```
┌─────────────────────────────────────┐
│  Takhlees Asset Management          │
│  Government Services                │
└─────────────────────────────────────┘
│                                     │
│  Password Reset Request             │
│                                     │
│  Hello [Username],                  │
│                                     │
│  We received a request to reset     │
│  your password.                     │
│                                     │
│     [Reset Password Button]         │
│                                     │
│  Or visit: [Reset Link URL]         │
│                                     │
│  Link expires in 1 hour             │
│                                     │
└─────────────────────────────────────┘
```

## Manual Token Testing (Development)

If email isn't working, you can test reset manually:

1. Check server console output when user requests reset:
```
✅ Password reset email sent to arsathfarvesh02@gmail.com
```

2. Or if email fails:
```
❌ Failed to send reset email to arsathfarvesh02@gmail.com: [error message]
```

3. Token is still valid in database, so reset functionality works

## Environment Variables Checklist

- [ ] `EMAIL_HOST` set (default: smtp.gmail.com)
- [ ] `EMAIL_PORT` set (default: 587)
- [ ] `EMAIL_USER` set to sender address
- [ ] `EMAIL_PASS` set to app password or SMTP password
- [ ] `APP_URL` set (optional, for production)
- [ ] Server restarted after updating .env

## Files Modified

- `server.js` - Added email transporter configuration (lines 12-25)
- `server.js` - Updated forgot-password endpoint to send emails (lines 1075-1150)
- `.env.example` - Email variables documented

## Next Steps

1. Copy `.env.example` to `.env` if you haven't already
2. Add your email credentials to `.env`
3. Restart the server
4. Test by requesting a password reset
5. Verify email arrives in inbox

For questions or issues, check server console output (`npm start`) for detailed error messages.
