const bcrypt = require('bcrypt');
const pool = require('../config/database');
const logger = require('../config/logger');

class AuthService {
  normalizeText(value) {
    if (value === undefined || value === null) {
      return null;
    }

    const normalized = String(value).trim();
    return normalized ? normalized : null;
  }

  normalizeAvatarUrl(value) {
    const normalized = this.normalizeText(value);
    if (!normalized) {
      return { value: null };
    }

    const isHttpsUrl = /^https?:\/\//i.test(normalized);
    const isRelativePath = normalized.startsWith('/');
    const isDataImage = /^data:image\/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=\s]+$/i.test(normalized);

    if (!isHttpsUrl && !isRelativePath && !isDataImage) {
      return {
        error: 'Avatar must be an https URL, a site-relative path, or a valid image data URL'
      };
    }

    return { value: normalized };
  }

  sanitizeUser(user) {
    if (!user) {
      return null;
    }

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      department: user.department,
      first_name: user.first_name || null,
      last_name: user.last_name || null,
      office_location: user.office_location || null,
      phone: user.phone || null,
      avatar_url: user.avatar_url || user.avatar || null
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

  // Get user statistics (admin only)
  async getUserStats() {
    try {
      const summary = await pool.query(`
        SELECT
          COUNT(*)                                                  AS total_users,
          COUNT(*) FILTER (WHERE role = 'admin')                   AS admins,
          COUNT(*) FILTER (WHERE role = 'user')                    AS normal_users,
          COUNT(*) FILTER (WHERE role = 'guest')                   AS guests,
          COUNT(*) FILTER (WHERE email IS NOT NULL AND email <> '') AS has_email,
          COUNT(*) FILTER (WHERE department IS NOT NULL AND department <> '') AS has_department,
          COUNT(*) FILTER (WHERE first_name IS NOT NULL AND first_name <> '') AS has_first_name,
          COUNT(*) FILTER (
            WHERE email IS NOT NULL AND email <> ''
              AND department IS NOT NULL AND department <> ''
          ) AS fully_complete
        FROM users
      `);

      const detail = await pool.query(`
        SELECT
          id, username, email, role, department,
          first_name, last_name, office_location, phone,
          created_at,
          CASE
            WHEN email IS NOT NULL AND email <> ''
             AND department IS NOT NULL AND department <> ''
             AND first_name IS NOT NULL AND first_name <> ''
            THEN 'complete'
            WHEN (email IS NULL OR email = '')
             AND (department IS NULL OR department = '')
             AND (first_name IS NULL OR first_name = '')
            THEN 'empty'
            ELSE 'partial'
          END AS data_status
        FROM users
        ORDER BY role, created_at ASC
      `);

      const s = summary.rows[0];
      return {
        success: true,
        summary: {
          total:           Number(s.total_users),
          admins:          Number(s.admins),
          normal_users:    Number(s.normal_users),
          guests:          Number(s.guests),
          has_email:       Number(s.has_email),
          has_department:  Number(s.has_department),
          has_first_name:  Number(s.has_first_name),
          fully_complete:  Number(s.fully_complete),
          incomplete:      Number(s.total_users) - Number(s.fully_complete)
        },
        users: detail.rows.map((u) => this.sanitizeUser(u))
      };
    } catch (error) {
      logger.error('getUserStats error:', error);
      return { success: false, error: 'Failed to fetch user stats' };
    }
  }

  // Create a new user (admin only)
  async createUser({ username, email, password, role, department, first_name, last_name, office_location, phone }) {
    try {
      if (!username || !String(username).trim()) {
        return { success: false, error: 'Username is required' };
      }
      if (!email || !String(email).trim()) {
        return { success: false, error: 'Email is required' };
      }
      if (!password || password.length < 8) {
        return { success: false, error: 'Password must be at least 8 characters' };
      }

      const normalizedUsername = String(username).trim();
      const normalizedRole = ['admin', 'user', 'guest'].includes(role) ? role : 'user';

      const dupUser = await pool.query(
        'SELECT id FROM users WHERE lower(username) = lower($1) LIMIT 1',
        [normalizedUsername]
      );
      if (dupUser.rows.length > 0) {
        return { success: false, error: 'Username already exists' };
      }

      const dupEmail = await pool.query(
        'SELECT id FROM users WHERE lower(email) = lower($1) LIMIT 1',
        [String(email).trim()]
      );
      if (dupEmail.rows.length > 0) {
        return { success: false, error: 'Email already exists' };
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const result = await pool.query(
        `INSERT INTO users
           (username, email, password, role, department, first_name, last_name, office_location, phone, avatar_url)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id, username, email, role, department, first_name, last_name, office_location, phone, avatar_url`,
        [
          normalizedUsername,
          String(email).trim(),
          hashedPassword,
          normalizedRole,
          department || null,
          first_name || null,
          last_name || null,
          office_location || null,
          phone || null,
          null
        ]
      );

      logger.info(`New user created by admin: ${normalizedUsername}`);
      return { success: true, user: this.sanitizeUser(result.rows[0]) };
    } catch (error) {
      logger.error('Create user error:', error);
      return { success: false, error: 'Failed to create user' };
    }
  }

  // Get all users (admin only)
  async getAllUsers() {
    try {
      const result = await pool.query(
        `SELECT id, username, email, role, department,
                first_name, last_name, office_location, phone, avatar_url,
                created_at
         FROM users ORDER BY created_at DESC`
      );
      return { success: true, users: result.rows.map((user) => this.sanitizeUser(user)) };
    } catch (error) {
      logger.error('Get users error:', error);
      return { success: false, error: 'Failed to fetch users' };
    }
  }

  // Update user profile
  async updateProfile(userId, updates) {
    try {
      const {
        email,
        department,
        password,
        first_name,
        last_name,
        office_location,
        phone,
        avatar_url
      } = updates;

      const normalizedEmail = this.normalizeText(email);
      const normalizedDepartment = this.normalizeText(department);
      const normalizedFirstName = this.normalizeText(first_name);
      const normalizedLastName = this.normalizeText(last_name);
      const normalizedOfficeLocation = this.normalizeText(office_location);
      const normalizedPhone = this.normalizeText(phone);
      const avatarNormalization = this.normalizeAvatarUrl(avatar_url);

      if (avatarNormalization.error) {
        return { success: false, error: avatarNormalization.error };
      }

      const duplicateEmail = await pool.query(
        'SELECT id FROM users WHERE lower(email) = lower($1) AND id <> $2 LIMIT 1',
        [normalizedEmail, userId]
      );

      if (duplicateEmail.rows.length > 0) {
        return { success: false, error: 'Email already exists' };
      }

      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
          `UPDATE users
           SET email = $1,
               department = $2,
               first_name = $3,
               last_name = $4,
               office_location = $5,
               phone = $6,
               avatar_url = $7,
               password = $8
           WHERE id = $9`,
          [
            normalizedEmail,
            normalizedDepartment,
            normalizedFirstName,
            normalizedLastName,
            normalizedOfficeLocation,
            normalizedPhone,
            avatarNormalization.value,
            hashedPassword,
            userId
          ]
        );
      } else {
        await pool.query(
          `UPDATE users
           SET email = $1,
               department = $2,
               first_name = $3,
               last_name = $4,
               office_location = $5,
               phone = $6,
               avatar_url = $7
           WHERE id = $8`,
          [
            normalizedEmail,
            normalizedDepartment,
            normalizedFirstName,
            normalizedLastName,
            normalizedOfficeLocation,
            normalizedPhone,
            avatarNormalization.value,
            userId
          ]
        );
      }

      const result = await pool.query(
        `SELECT id, username, email, role, department,
                first_name, last_name, office_location, phone, avatar_url
         FROM users WHERE id = $1`,
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
      const {
        username,
        email,
        department,
        role,
        password,
        first_name,
        last_name,
        office_location,
        phone,
        avatar_url
      } = updates;

      if (!username || !String(username).trim()) {
        return { success: false, error: 'Username is required' };
      }

      const normalizedUsername = String(username).trim();
      const normalizedEmail = this.normalizeText(email);
      const normalizedRole = ['admin', 'user', 'guest'].includes(role) ? role : 'user';
      const normalizedDepartment = this.normalizeText(department);
      const normalizedFirstName = this.normalizeText(first_name);
      const normalizedLastName = this.normalizeText(last_name);
      const normalizedOfficeLocation = this.normalizeText(office_location);
      const normalizedPhone = this.normalizeText(phone);
      const avatarNormalization = this.normalizeAvatarUrl(avatar_url);

      if (avatarNormalization.error) {
        return { success: false, error: avatarNormalization.error };
      }

      const exists = await pool.query(
        'SELECT id FROM users WHERE lower(username) = lower($1) AND id <> $2 LIMIT 1',
        [normalizedUsername, targetUserId]
      );

      if (exists.rows.length > 0) {
        return { success: false, error: 'Username already exists' };
      }

      const duplicateEmail = await pool.query(
        'SELECT id FROM users WHERE lower(email) = lower($1) AND id <> $2 LIMIT 1',
        [normalizedEmail, targetUserId]
      );

      if (duplicateEmail.rows.length > 0) {
        return { success: false, error: 'Email already exists' };
      }

      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
          `UPDATE users
           SET username = $1,
               email = $2,
               department = $3,
               role = $4,
               first_name = $5,
               last_name = $6,
               office_location = $7,
               phone = $8,
               avatar_url = $9,
               password = $10
           WHERE id = $11`,
          [
            normalizedUsername,
            normalizedEmail,
            normalizedDepartment,
            normalizedRole,
            normalizedFirstName,
            normalizedLastName,
            normalizedOfficeLocation,
            normalizedPhone,
            avatarNormalization.value,
            hashedPassword,
            targetUserId
          ]
        );
      } else {
        await pool.query(
          `UPDATE users
           SET username = $1,
               email = $2,
               department = $3,
               role = $4,
               first_name = $5,
               last_name = $6,
               office_location = $7,
               phone = $8,
               avatar_url = $9
           WHERE id = $10`,
          [
            normalizedUsername,
            normalizedEmail,
            normalizedDepartment,
            normalizedRole,
            normalizedFirstName,
            normalizedLastName,
            normalizedOfficeLocation,
            normalizedPhone,
            avatarNormalization.value,
            targetUserId
          ]
        );
      }

      const result = await pool.query(
        `SELECT id, username, email, role, department,
                first_name, last_name, office_location, phone, avatar_url
         FROM users WHERE id = $1`,
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
