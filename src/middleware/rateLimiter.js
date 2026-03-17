const rateLimit = require('express-rate-limit');

// General API rate limiter
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: { success: false, error: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    const path = req.path || '';

    // Login/CSRF endpoints are protected separately by authLimiter and should
    // not be throttled by the global API limiter.
    return (
      path === '/csrf-token' ||
      path === '/login' ||
      path.startsWith('/auth/')
    );
  }
});

// Stricter rate limiter for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: { success: false, error: "Too many login attempts, please try again later" },
  skipSuccessfulRequests: true
});

module.exports = {
  apiLimiter,
  authLimiter
};
