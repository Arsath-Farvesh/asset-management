const authService = require('../../src/services/authService');
const pool = require('../../src/config/database');
const bcrypt = require('bcrypt');

// Mock database pool
jest.mock('../../src/config/database');
jest.mock('bcrypt');

describe('AuthService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('login', () => {
    it('should successfully login with valid credentials', async () => {
      const mockUser = {
        id: 1,
        username: 'testuser',
        password: 'hashedpassword',
        email: 'test@example.com',
        role: 'user',
        department: 'IT'
      };

      pool.query = jest.fn().mockResolvedValue({ rows: [mockUser] });
      bcrypt.compare = jest.fn().mockResolvedValue(true);

      const result = await authService.login('testuser', 'password123');

      expect(result.success).toBe(true);
      expect(result.user.username).toBe('testuser');
      expect(result.user.email).toBe('test@example.com');
    });

    it('should fail login with invalid username', async () => {
      pool.query = jest.fn().mockResolvedValue({ rows: [] });

      const result = await authService.login('nonexistent', 'password123');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
    });

    it('should fail login with invalid password', async () => {
      const mockUser = {
        id: 1,
        username: 'testuser',
        password: 'hashedpassword'
      };

      pool.query = jest.fn().mockResolvedValue({ rows: [mockUser] });
      bcrypt.compare = jest.fn().mockResolvedValue(false);

      const result = await authService.login('testuser', 'wrongpassword');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
    });
  });

  describe('getAllUsers', () => {
    it('should return all users', async () => {
      const mockUsers = [
        { id: 1, username: 'user1', email: 'user1@test.com', role: 'user' },
        { id: 2, username: 'user2', email: 'user2@test.com', role: 'admin' }
      ];

      pool.query = jest.fn().mockResolvedValue({ rows: mockUsers });

      const result = await authService.getAllUsers();

      expect(result.success).toBe(true);
      expect(result.users).toHaveLength(2);
    });
  });

  describe('updateProfile', () => {
    it('should update only email and department for self profile without username changes', async () => {
      pool.query = jest.fn()
        .mockResolvedValueOnce({ rowCount: 1 })
        .mockResolvedValueOnce({
          rows: [{ id: 1, username: 'user1', email: 'updated@test.com', role: 'user', department: 'Ops' }]
        });

      const result = await authService.updateProfile(1, {
        email: 'updated@test.com',
        department: 'Ops'
      });

      expect(result.success).toBe(true);
      expect(pool.query).toHaveBeenNthCalledWith(
        1,
        'UPDATE users SET email = $1, department = $2 WHERE id = $3',
        ['updated@test.com', 'Ops', 1]
      );
      expect(result.user.username).toBe('user1');
    });
  });

  describe('updateUserAsAdmin', () => {
    it('should reject duplicate usernames', async () => {
      pool.query = jest.fn().mockResolvedValueOnce({ rows: [{ id: 99 }] });

      const result = await authService.updateUserAsAdmin(2, {
        username: 'existing',
        email: 'user@test.com',
        department: 'IT',
        role: 'user'
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Username already exists');
    });

    it('should update a managed user including username and role', async () => {
      pool.query = jest.fn()
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rowCount: 1 })
        .mockResolvedValueOnce({
          rows: [{ id: 2, username: 'renamed', email: 'renamed@test.com', role: 'admin', department: 'Finance' }]
        });

      const result = await authService.updateUserAsAdmin(2, {
        username: 'renamed',
        email: 'renamed@test.com',
        department: 'Finance',
        role: 'admin'
      });

      expect(result.success).toBe(true);
      expect(pool.query).toHaveBeenNthCalledWith(
        2,
        'UPDATE users SET username = $1, email = $2, department = $3, role = $4 WHERE id = $5',
        ['renamed', 'renamed@test.com', 'Finance', 'admin', 2]
      );
      expect(result.user.role).toBe('admin');
    });
  });
});
