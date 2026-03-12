const authService = require('../services/authService');
const { validationResult } = require('express-validator');
const logger = require('../config/logger');

class AuthController {
  // Login
  async login(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { username, password } = req.body;
    const result = await authService.login(username, password);

    if (!result.success) {
      return res.status(401).json(result);
    }

    req.session.user = result.user;
    return res.json({ success: true, user: result.user });
  }

  // Logout
  logout(req, res) {
    req.session.destroy((err) => {
      if (err) {
        logger.error('Logout error:', err);
        return res.status(500).json({ success: false, error: 'Logout failed' });
      }
      res.json({ success: true, message: 'Logged out successfully' });
    });
  }

  // Check authentication status
  checkAuth(req, res) {
    if (req.session && req.session.user) {
      return res.json({ authenticated: true, user: req.session.user });
    }
    res.json({ authenticated: false });
  }

  // Get auth status
  getAuthStatus(req, res) {
    if (req.session && req.session.user) {
      return res.json({ authenticated: true, user: req.session.user });
    }
    res.json({ authenticated: false });
  }

  // Get current user info
  getMe(req, res) {
    if (req.session && req.session.user) {
      return res.json({ success: true, user: req.session.user });
    }
    res.status(401).json({ success: false, error: 'Not authenticated' });
  }

  // Get all users (admin only)
  async getAllUsers(req, res) {
    const result = await authService.getAllUsers();
    
    if (!result.success) {
      return res.status(500).json(result);
    }

    res.json(result);
  }

  // Update user profile
  async updateProfile(req, res) {
    const { username, email, department, password, confirmPassword } = req.body;

    if (password && password !== confirmPassword) {
      return res.status(400).json({ success: false, error: 'Passwords do not match' });
    }

    if (password && password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
    }

    const userId = req.session.user.id;
    const result = await authService.updateProfile(userId, { username, email, department, password });

    if (!result.success) {
      return res.status(500).json(result);
    }

    // Update session
    req.session.user = { ...req.session.user, ...result.user };
    res.json(result);
  }
}

module.exports = new AuthController();
