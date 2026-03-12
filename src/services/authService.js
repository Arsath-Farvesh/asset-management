const bcrypt = require('bcrypt');
const pool = require('../config/database');
const logger = require('../config/logger');

class AuthService {
  sanitizeUser(user) {
    if (!user) {
      return null;
    }

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      department: user.department
    };
  }

  // Login user
  async login(username, password) {
    try {
      const result = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
      );

      if (result.rows.length === 0) {
        return { success: false, error: 'Invalid credentials' };
      }

      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return { success: false, error: 'Invalid credentials' };
      }

      logger.info(`User logged in: ${username}`);
      return { 
        success: true, 
        user: this.sanitizeUser(user)
      };
    } catch (error) {
      logger.error('Login error:', error);
      return { success: false, error: 'Login failed' };
    }
  }

  // Get all users (admin only)
  async getAllUsers() {
    try {
      const result = await pool.query(
        'SELECT id, username, email, role, department, created_at FROM users ORDER BY created_at DESC'
      );
      return { success: true, users: result.rows };
    } catch (error) {
      logger.error('Get users error:', error);
      return { success: false, error: 'Failed to fetch users' };
    }
  }

  // Update user profile
  async updateProfile(userId, updates) {
    try {
      const { email, department, password } = updates;
      
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
          'UPDATE users SET email = $1, department = $2, password = $3 WHERE id = $4',
          [email, department, hashedPassword, userId]
        );
      } else {
        await pool.query(
          'UPDATE users SET email = $1, department = $2 WHERE id = $3',
          [email, department, userId]
        );
      }

      const result = await pool.query(
        'SELECT id, username, email, role, department FROM users WHERE id = $1',
        [userId]
      );

      logger.info(`Profile updated for user ID: ${userId}`);
      return { success: true, user: this.sanitizeUser(result.rows[0]) };
    } catch (error) {
      logger.error('Update profile error:', error);
      return { success: false, error: 'Failed to update profile' };
    }
  }

  async updateUserAsAdmin(targetUserId, updates) {
    try {
      const { username, email, department, role, password } = updates;

      if (!username || !String(username).trim()) {
        return { success: false, error: 'Username is required' };
      }

      const normalizedUsername = String(username).trim();
      const normalizedRole = ['admin', 'user', 'guest'].includes(role) ? role : 'user';

      const exists = await pool.query(
        'SELECT id FROM users WHERE lower(username) = lower($1) AND id <> $2 LIMIT 1',
        [normalizedUsername, targetUserId]
      );

      if (exists.rows.length > 0) {
        return { success: false, error: 'Username already exists' };
      }

      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
          'UPDATE users SET username = $1, email = $2, department = $3, role = $4, password = $5 WHERE id = $6',
          [normalizedUsername, email, department, normalizedRole, hashedPassword, targetUserId]
        );
      } else {
        await pool.query(
          'UPDATE users SET username = $1, email = $2, department = $3, role = $4 WHERE id = $5',
          [normalizedUsername, email, department, normalizedRole, targetUserId]
        );
      }

      const result = await pool.query(
        'SELECT id, username, email, role, department FROM users WHERE id = $1',
        [targetUserId]
      );

      if (result.rows.length === 0) {
        return { success: false, error: 'User not found' };
      }

      return { success: true, user: this.sanitizeUser(result.rows[0]) };
    } catch (error) {
      logger.error('Admin update user error:', error);
      return { success: false, error: 'Failed to update user' };
    }
  }
}

module.exports = new AuthService();
