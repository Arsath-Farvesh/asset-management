const logger = require('../config/logger');

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
  logger.error('Error:', err);
  
  res.status(err.status || 500).json({ 
    success: false, 
    error: err.message || 'Internal server error' 
  });
};

module.exports = {
  sanitizeInput,
  requestLogger,
  csrfErrorHandler,
  errorHandler
};
