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
    const { email, department, password, confirmPassword } = req.body;

    if (password && password !== confirmPassword) {
      return res.status(400).json({ success: false, error: 'Passwords do not match' });
    }

    if (password && password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
    }

    const userId = req.session.user.id;
    const result = await authService.updateProfile(userId, { email, department, password });

    if (!result.success) {
      return res.status(500).json(result);
    }

    // Update session
    req.session.user = { ...req.session.user, ...result.user };
    res.json(result);
  }

  // Get user statistics (admin only)
  async getUserStats(req, res) {
    const result = await authService.getUserStats();
    if (!result.success) {
      return res.status(500).json(result);
    }
    return res.json(result);
  }

  async createUser(req, res) {
    const {
      username, email, password, confirmPassword,
      role, department, first_name, last_name, office_location, phone
    } = req.body;

    if (!username || !String(username).trim()) {
      return res.status(400).json({ success: false, error: 'Username is required' });
    }
    if (!email || !String(email).trim()) {
      return res.status(400).json({ success: false, error: 'Email is required' });
    }
    if (!password) {
      return res.status(400).json({ success: false, error: 'Password is required' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, error: 'Passwords do not match' });
    }
    if (password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
    }

    const result = await authService.createUser({
      username, email, password, role, department,
      first_name, last_name, office_location, phone
    });

    if (!result.success) {
      return res.status(400).json(result);
    }

    return res.status(201).json(result);
  }

  async updateUser(req, res) {
    const { id } = req.params;
    const { username, email, department, role, password, confirmPassword } = req.body;

    if (password && password !== confirmPassword) {
      return res.status(400).json({ success: false, error: 'Passwords do not match' });
    }

    if (password && password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
    }

    const targetUserId = Number.parseInt(id, 10);
    if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const result = await authService.updateUserAsAdmin(targetUserId, {
      username,
      email,
      department,
      role,
      password
    });

    if (!result.success) {
      const status = result.error === 'User not found' ? 404 : 400;
      return res.status(status).json(result);
    }

    if (req.session?.user?.id === targetUserId) {
      req.session.user = { ...req.session.user, ...result.user };
    }

    return res.json(result);
  }
}

module.exports = new AuthController();
