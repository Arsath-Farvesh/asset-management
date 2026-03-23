const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'YOUR_GOOGLE_CLIENT_SECRET',
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = {
      id: profile.id,
      username: profile.displayName || profile.emails[0].value.split('@')[0],
      email: profile.emails[0].value,
      provider: 'google',
      avatar: profile.photos[0]?.value,
      role: 'user'
    };
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// Microsoft OAuth Strategy
passport.use(new MicrosoftStrategy({
  clientID: process.env.MICROSOFT_CLIENT_ID || 'YOUR_MICROSOFT_CLIENT_ID',
  clientSecret: process.env.MICROSOFT_CLIENT_SECRET || 'YOUR_MICROSOFT_CLIENT_SECRET',
  callbackURL: process.env.MICROSOFT_CALLBACK_URL || 'http://localhost:3000/auth/microsoft/callback',
  scope: ['user.read']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = {
      id: profile.id,
      username: profile.displayName || profile.emails[0].value.split('@')[0],
      email: profile.emails[0].value,
      provider: 'microsoft',
      avatar: profile.photos?.[0]?.value,
      role: 'user'
    };
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// GitHub OAuth Strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID || 'YOUR_GITHUB_CLIENT_ID',
  clientSecret: process.env.GITHUB_CLIENT_SECRET || 'YOUR_GITHUB_CLIENT_SECRET',
  callbackURL: process.env.GITHUB_CALLBACK_URL || 'http://localhost:3000/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = {
      id: profile.id,
      username: profile.username || profile.displayName,
      email: profile.emails?.[0]?.value,
      provider: 'github',
      avatar: profile.photos?.[0]?.value,
      role: 'user'
    };
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

module.exports = passport;
