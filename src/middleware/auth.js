const logger = require('../config/logger');

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ 
    success: false, 
    error: 'Not authenticated. Please log in.' 
  });
};

// Admin authorization middleware
const isAdmin = (req, res, next) => {
  if (req.session && req.session.user && req.session.user.role === 'admin') {
    return next();
  }
  logger.warn(`Unauthorized admin access attempt by user: ${req.session?.user?.username || 'unknown'}`);
  return res.status(403).json({ 
    success: false, 
    error: 'Forbidden. Admin access required.' 
  });
};

module.exports = {
  isAuthenticated,
  isAdmin
};
