# OAuth Setup Guide

This document explains how to set up Google, Microsoft, and GitHub OAuth authentication for the Takhlees Asset Management System.

## Overview

The system now supports OAuth sign-in through:
- **Google** - Google Sign-In
- **Microsoft** - Azure AD / Microsoft Account
- **GitHub** - GitHub OAuth

Users can authenticate using their existing credentials from any of these providers OR use the traditional username/password login.

## Environment Variables Required

Add these to your `.env` file:

```env
# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# Microsoft OAuth
MICROSOFT_CLIENT_ID=your_microsoft_client_id_here
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret_here
MICROSOFT_CALLBACK_URL=http://localhost:3000/auth/microsoft/callback
MICROSOFT_TENANT=common

# GitHub OAuth
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
GITHUB_CALLBACK_URL=http://localhost:3000/auth/github/callback
```

## Setup Instructions by Provider

### 1. Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the **Google+ API**
4. Go to **Credentials** → Create OAuth 2.0 Client ID
5. Choose "Web application"
6. Add authorized redirect URIs:
   - `http://localhost:3000/auth/google/callback` (development)
   - `https://yourdomain.com/auth/google/callback` (production)
7. Copy the Client ID and Client Secret
8. Add them to `.env` as `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`

### 2. Microsoft OAuth Setup

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Fill in:
   - Name: "Takhlees Asset Management"
   - Supported account types: "Accounts in any organizational directory and personal Microsoft accounts"
5. Go to **Certificates & secrets** → Create new client secret
6. Copy the secret value
7. Go to **Authentication** → Add redirect URI:
   - `http://localhost:3000/auth/microsoft/callback` (development)
   - `https://yourdomain.com/auth/microsoft/callback` (production)
8. Add to `.env`:
   - `MICROSOFT_CLIENT_ID` = Application (client) ID from Overview
   - `MICROSOFT_CLIENT_SECRET` = The secret value
   - `MICROSOFT_TENANT` = "common" or your specific tenant ID

### 3. GitHub OAuth Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **OAuth Apps** → **New OAuth App**
3. Fill in:
   - Application name: "Takhlees Asset Management"
   - Homepage URL: `http://localhost:3000` (development) or your domain
   - Authorization callback URL: `http://localhost:3000/auth/github/callback`
4. Copy the Client ID and generate a new Client Secret
5. Add to `.env`:
   - `GITHUB_CLIENT_ID`
   - `GITHUB_CLIENT_SECRET`
   - `GITHUB_CALLBACK_URL`

## Production Deployment

When deploying to production:

1. Update all `*_CALLBACK_URL` environment variables to use your production domain:
   ```
   GOOGLE_CALLBACK_URL=https://yourdomain.com/auth/google/callback
   MICROSOFT_CALLBACK_URL=https://yourdomain.com/auth/microsoft/callback
   GITHUB_CALLBACK_URL=https://yourdomain.com/auth/github/callback
   ```

2. Update the OAuth apps/credentials in each provider's console to add your production callback URLs

3. Ensure `NODE_ENV=production` and secure cookies are enabled (they are by default in production)

## User Flow

### First-time OAuth Login
1. User clicks Google/Microsoft/GitHub button on login page
2. Redirected to provider's login page
3. User authorizes the app
4. Returned to `/auth/{provider}/callback`
5. Session created with user info from provider
6. Redirected to home page (`/index.html`)
7. Auth indicator shows username from provider

### Subsequent Logins
1. User clicks relevant OAuth button
2. If already logged in with provider, skips auth
3. Immediately returns and creates session

### Session Data
OAuth sessions include:
- `username` - From provider (display name or email username)
- `email` - User's email address
- `role` - Set to 'user' by default
- `provider` - 'google', 'microsoft', or 'github'
- `avatar` - Profile picture URL (if available)

## Troubleshooting

**Issue**: "Invalid client ID" or "Client not found"
- **Solution**: Verify CLIENT_ID and CLIENT_SECRET are correct in `.env`

**Issue**: "Redirect URI mismatch"
- **Solution**: Ensure the callback URL matches exactly in both your code and provider settings (including protocol and domain)

**Issue**: Session not persisting
- **Solution**: Check that SESSION_SECRET is set in `.env` and database session storage is configured

**Issue**: Profile picture not loading
- **Solution**: Some providers may not expose photos. GitHub requires public email scope. This is optional.

## Security Notes

- Sensitive credentials (CLIENT_SECRET) are stored in `.env` (production: environment variables)
- Passwords in `validatePasswordStrength()` are never required for OAuth users
- Sessions use httpOnly, secure, and sameSite cookies whenever possible
- OAuth user data is stored in session only, not in database (can be extended)

## Feature Combination

Users can:
✅ Sign up with OAuth (creates session)
✅ Sign in with OAuth on future visits
✅ Use traditional username/password login
✅ Both methods coexist and can switch between them

The auth indicator correctly displays whoever is currently logged in, regardless of authentication method.
