const bcrypt = require('bcrypt');
const pool = require('../config/database');
const logger = require('../config/logger');

class AuthService {
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
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          department: user.department
        }
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
      return { success: true, user: result.rows[0] };
    } catch (error) {
      logger.error('Update profile error:', error);
      return { success: false, error: 'Failed to update profile' };
    }
  }
}

module.exports = new AuthService();
