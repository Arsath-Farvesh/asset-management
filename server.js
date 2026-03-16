require('dotenv').config();

const { validateEnvironment } = require('./src/config/env');

const envValidation = validateEnvironment();
if (envValidation.warnings.length > 0 && process.env.NODE_ENV !== 'test') {
  envValidation.warnings.forEach((warning) => {
    console.warn(`[ENV WARNING] ${warning}`);
  });
}

if (envValidation.errors.length > 0 && process.env.NODE_ENV !== 'test') {
  envValidation.errors.forEach((error) => {
    console.error(`[ENV ERROR] ${error}`);
  });
  process.exit(1);
}

const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const csrf = require('csurf');
const compression = require('compression');
const pgSession = require('connect-pg-simple')(require('express-session'));
const swaggerUi = require('swagger-ui-express');

// Import configurations
const pool = require('./src/config/database');
const logger = require('./src/config/logger');
const passport = require('./src/config/passport');
const swaggerSpec = require('./src/config/swagger');

// Import middleware
const { attachRequestContext, requestLogger, sanitizeInput, csrfErrorHandler, errorHandler } = require('./src/middleware/security');
const { apiLimiter } = require('./src/middleware/rateLimiter');

// Import routes
const routes = require('./src/routes');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT_NAME === 'production';
const isStrictCsp = process.env.CSP_MODE === 'strict';
const isCspReportOnly = process.env.CSP_REPORT_ONLY === 'true';
const railwayPublicOrigin = process.env.RAILWAY_PUBLIC_DOMAIN
  ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
  : null;

function normalizeOrigin(origin) {
  if (!origin || typeof origin !== 'string') {
    return null;
  }

  try {
    const parsed = new URL(origin.trim());
    return parsed.origin;
  } catch (error) {
    return null;
  }
}

const allowedOrigins = new Set(
  [...(process.env.CORS_ORIGINS || '').split(','), railwayPublicOrigin]
    .map((origin) => normalizeOrigin(origin))
    .filter(Boolean)
);

function buildCspDirectives() {
  const baseDirectives = {
    defaultSrc: ["'self'"],
    styleSrc: ["'self'", 'https://cdn.jsdelivr.net', 'https://fonts.googleapis.com'],
    scriptSrc: ["'self'", 'https://cdn.jsdelivr.net', 'https://html2canvas.hertzen.com', 'https://unpkg.com'],
    fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdn.jsdelivr.net'],
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'"]
  };

  if (isStrictCsp) {
    return baseDirectives;
  }

  return {
    ...baseDirectives,
    styleSrc: [...baseDirectives.styleSrc, "'unsafe-inline'"],
    scriptSrc: [...baseDirectives.scriptSrc, "'unsafe-inline'"]
  };
}

app.disable('x-powered-by');

// ===== FAST LIVENESS HEALTH CHECK =====
// Keep this route before heavier middleware (session/csrf/logging) so deployment
// health checks remain fast and don't depend on DB-backed session reads.
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ===== SECURITY HEADERS =====
app.use(helmet({
  contentSecurityPolicy: {
    directives: buildCspDirectives(),
    reportOnly: isCspReportOnly
  }
}));

// ===== COMPRESSION MIDDLEWARE (GZIP) =====
app.use(compression({
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  },
  level: 6
}));

// ===== RATE LIMITING =====
app.use('/api/', apiLimiter);

// ===== CORS CONFIGURATION =====
app.use(cors((req, callback) => {
  const requestOrigin = normalizeOrigin(req.get('origin'));
  const requestHost = req.get('host');
  const forwardedProto = (req.get('x-forwarded-proto') || req.protocol || 'https').split(',')[0].trim();
  const sameOrigin = requestOrigin && requestHost && requestOrigin === `${forwardedProto}://${requestHost}`;

  // Allow non-browser calls, development calls, same-origin browser calls, or approved origins.
  if (!requestOrigin || !isProduction || sameOrigin || allowedOrigins.has(requestOrigin)) {
    return callback(null, { origin: true, credentials: true });
  }

  logger.warn('Blocked CORS origin', {
    origin: requestOrigin,
    path: req.originalUrl
  });

  // Reject disallowed origins without throwing a 500.
  return callback(null, { origin: false, credentials: true });
}));

app.set('trust proxy', 1);

// ===== REQUEST LOGGING =====
app.use(attachRequestContext);
app.use(requestLogger);

// ===== BODY PARSERS =====
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(bodyParser.json({ limit: '1mb' }));

// ===== STATIC FILES =====
app.use(express.static(path.join(__dirname, 'public')));

// ===== SESSION CONFIGURATION =====
// 30 minutes of inactivity = automatic logout (1800000 ms)
const INACTIVITY_TIMEOUT = Number.parseInt(process.env.SESSION_INACTIVITY_TIMEOUT, 10) || 30 * 60 * 1000;
// Maximum session duration regardless of activity (24 hours)
const MAX_SESSION_AGE = Number.parseInt(process.env.SESSION_MAX_AGE, 10) || 24 * 60 * 60 * 1000;
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'takhlees.sid';

app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session',
    createTableIfMissing: true,
    errorLog: (err) => logger.error('Session store error:', err),
    disableTouch: false
  }),
  name: SESSION_COOKIE_NAME,
  secret: process.env.SESSION_SECRET || "change_this_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: MAX_SESSION_AGE,
    domain: process.env.SESSION_COOKIE_DOMAIN || undefined
  }
}));

// ===== PASSPORT INITIALIZATION =====
app.use(passport.initialize());
app.use(passport.session());

function respondToExpiredSession(req, res) {
  res.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    domain: process.env.SESSION_COOKIE_DOMAIN || undefined
  });

  if (req.originalUrl.startsWith('/api/')) {
    return res.status(401).json({
      success: false,
      error: 'Session expired due to inactivity',
      code: 'SESSION_EXPIRED'
    });
  }

  return res.redirect(`/login.html?reason=${encodeURIComponent('Session expired due to inactivity')}`);
}

// ===== ACTIVITY TRACKING AND INACTIVITY ENFORCEMENT =====
app.use((req, res, next) => {
  const isAuthenticated = typeof req.isAuthenticated === 'function'
    ? req.isAuthenticated()
    : Boolean(req.session && req.session.user);

  if (!isAuthenticated || !req.session) {
    return next();
  }

  const now = Date.now();
  const lastActivity = Number(req.session.lastActivity || now);

  if (now - lastActivity > INACTIVITY_TIMEOUT) {
    return req.session.destroy((error) => {
      if (error) {
        logger.error('Failed to destroy expired session:', error);
      }
      return respondToExpiredSession(req, res);
    });
  }

  req.session.touch();
  req.session.lastActivity = now;
  return next();
});

// ===== CSRF PROTECTION =====
const csrfProtection = csrf({ cookie: false });
app.use((req, res, next) => {
  const isLoginEndpoint = req.method === 'POST' && (req.path === '/api/login' || req.path === '/api/auth/login');
  if (isLoginEndpoint) {
    return next();
  }

  return csrfProtection(req, res, next);
});

// ===== INPUT SANITIZATION & VALIDATION =====
app.use(sanitizeInput);

// ===== API DOCUMENTATION =====
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  explorer: true,
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Asset Management API'
}));

// ===== ROOT ROUTE =====
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// ===== CSRF TOKEN ENDPOINT =====
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ===== API ROUTES =====
app.use(routes);

// ===== CSRF ERROR HANDLER =====
app.use(csrfErrorHandler);

// ===== GLOBAL ERROR HANDLER =====
app.use(errorHandler);

// ===== RUN MIGRATIONS =====
async function runMigrations() {
  let migrationKnex = null;
  try {
    migrationKnex = require('knex')(require('./knexfile'));
    logger.info('🔄 Running database migrations...');
    const migrationsRun = await migrationKnex.migrate.latest();
    logger.info(`✅ Migrations completed. Files run: ${migrationsRun[1] ? migrationsRun[1].length : 0}`, { files: migrationsRun[1] || [] });
    await migrationKnex.destroy();
  } catch (err) {
    logger.error('Migration error:', {
      message: err.message,
      code: err.code,
      detail: err.detail
    });
    // Don't exit - allow app to start anyway (in case migrations are optional)
  }
}

// ===== START SERVER =====
// Only start server if not in test mode
if (process.env.NODE_ENV !== 'test') {
  (async () => {
    await runMigrations();
    app.listen(PORT, '0.0.0.0', () => {
      logger.info(`🚀 Server running on port ${PORT}`);
      logger.info(`📁 Serving static files from: ${path.join(__dirname, 'public')}`);
      logger.info(`🌐 Server bound to 0.0.0.0:${PORT}`);
      logger.info(`✅ Modular architecture loaded`);
    });
  })();

  // ===== GRACEFUL SHUTDOWN =====
  process.on('SIGTERM', () => {
    logger.info('SIGTERM received, closing server gracefully');
    process.exit(0);
  });

  process.on('SIGINT', () => {
    logger.info('SIGINT received, closing server gracefully');
    process.exit(0);
  });
}

// Export app for testing
module.exports = app;
