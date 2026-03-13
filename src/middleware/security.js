const logger = require('../config/logger');
const crypto = require('crypto');

// Correlate logs and responses with a request identifier.
const attachRequestContext = (req, res, next) => {
  const incomingRequestId = req.headers['x-request-id'];
  const requestId = typeof incomingRequestId === 'string' && incomingRequestId.trim()
    ? incomingRequestId.trim()
    : crypto.randomUUID();

  req.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  next();
};

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        // Remove HTML tags and dangerous characters
        req.body[key] = req.body[key].trim().replace(/<[^>]*>/g, '');
      }
    });
  }
  next();
};

// Request logging middleware
const requestLogger = (req, res, next) => {
  if (process.env.NODE_ENV !== 'production') {
    logger.info(`${req.method} ${req.path}`);
  }
  next();
};

// CSRF error handler
const csrfErrorHandler = (err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    logger.warn(`CSRF token validation failed for ${req.method} ${req.path}`);
    return res.status(403).json({ 
      success: false, 
      error: 'CSRF token validation failed. Please refresh and try again.' 
    });
  }
  next(err);
};

// Global error handler
const errorHandler = (err, req, res, next) => {
  const status = err.status || 500;
  const isProduction = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT_NAME === 'production';

  logger.error('Unhandled request error', {
    requestId: req.requestId,
    method: req.method,
    path: req.originalUrl,
    status,
    message: err.message,
    stack: err.stack
  });

  const responseError = status >= 500 && isProduction
    ? 'Internal server error'
    : (err.message || 'Internal server error');

  res.status(status).json({
    success: false,
    error: responseError,
    requestId: req.requestId
  });
};

module.exports = {
  attachRequestContext,
  sanitizeInput,
  requestLogger,
  csrfErrorHandler,
  errorHandler
};
