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
});
