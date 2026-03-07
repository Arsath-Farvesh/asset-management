require('dotenv').config();

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
const { requestLogger, sanitizeInput, csrfErrorHandler, errorHandler } = require('./src/middleware/security');
const { apiLimiter } = require('./src/middleware/rateLimiter');

// Import routes
const routes = require('./src/routes');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== SECURITY HEADERS =====
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://html2canvas.hertzen.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]
    }
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
app.use(cors({
  origin: "*",
  credentials: true
}));

app.set('trust proxy', 1);

// ===== REQUEST LOGGING =====
app.use(requestLogger);

// ===== BODY PARSERS =====
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// ===== STATIC FILES =====
app.use(express.static(path.join(__dirname, 'public')));

// ===== SESSION CONFIGURATION =====
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session',
    createTableIfMissing: true,
    errorLog: (err) => logger.error('Session store error:', err)
  }),
  secret: process.env.SESSION_SECRET || "change_this_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT_NAME === 'production',
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 2,
    domain: process.env.NODE_ENV === 'production' ? undefined : 'localhost'
  }
}));

// ===== PASSPORT INITIALIZATION =====
app.use(passport.initialize());
app.use(passport.session());

// ===== CSRF PROTECTION =====
const csrfProtection = csrf({ cookie: false });
app.use(csrfProtection);

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

// ===== API ROUTES =====
app.use(routes);

// ===== CSRF ERROR HANDLER =====
app.use(csrfErrorHandler);

// ===== GLOBAL ERROR HANDLER =====
app.use(errorHandler);

// ===== START SERVER =====
// Only start server if not in test mode
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, '0.0.0.0', () => {
    logger.info(`🚀 Server running on port ${PORT}`);
    logger.info(`📁 Serving static files from: ${path.join(__dirname, 'public')}`);
    logger.info(`🌐 Server bound to 0.0.0.0:${PORT}`);
    logger.info(`✅ Modular architecture loaded`);
  });

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
