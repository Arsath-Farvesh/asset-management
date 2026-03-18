const request = require('supertest');
const app = require('../../server');
const pool = require('../../src/config/database');

// Mock database
jest.mock('../../src/config/database');
jest.mock('../../src/config/email', () => ({
  sendMail: jest.fn().mockResolvedValue({ messageId: 'mock-id' })
}));

describe('Auth Routes Integration Tests', () => {
  let csrfToken;
  let agent;

  beforeEach(async () => {
    jest.clearAllMocks();
    process.env.EMAIL_USER = 'test@example.com';
    process.env.EMAIL_PASS = 'secret';
    agent = request.agent(app);
    
    // Get CSRF token
    const res = await agent.get('/api/csrf-token');
    csrfToken = res.body.csrfToken;
  });

  afterAll(async () => {
    // Close server connections
    if (app && app.close) {
      await app.close();
    }
  });

  describe('POST /api/auth/login', () => {
    it('should reject invalid credentials', async () => {
      pool.query = jest.fn().mockResolvedValue({ rows: [] });

      const response = await agent
        .post('/api/auth/login')
        .set('csrf-token', csrfToken)
        .send({ username: 'invalid', password: 'wrong' });

      expect([401, 403]).toContain(response.status);
    });
  });

  describe('GET /api/auth/me', () => {
    it('should require authentication', async () => {
      const response = await agent
        .get('/api/auth/me');

      expect(response.status).toBe(401);
    });
  });

  describe('GET /api/db-schema', () => {
    it('should reject unauthenticated users', async () => {
      const response = await agent.get('/api/db-schema');

      expect(response.status).toBe(401);
    });
  });

  describe('POST /api/auth/logout', () => {
    it('should handle logout request', async () => {
      const response = await agent
        .post('/api/auth/logout')
        .set('csrf-token', csrfToken);

      expect([200, 403]).toContain(response.status);
    });
  });

  describe('POST /api/forgot-password', () => {
    it('should handle reset request route', async () => {
      pool.query
        .mockResolvedValueOnce({ rows: [{ id: 1, username: 'john', email: 'john@example.com' }] })
        .mockResolvedValueOnce({ rows: [] });

      const response = await agent
        .post('/api/auth/forgot-password')
        .set('csrf-token', csrfToken)
        .send({ email: 'john@example.com' });

      expect([200, 403]).toContain(response.status);
    });
  });

  describe('POST /api/reset-password', () => {
    it('should reject invalid reset token', async () => {
      pool.query.mockResolvedValueOnce({ rows: [] });

      const response = await agent
        .post('/api/auth/reset-password')
        .set('csrf-token', csrfToken)
        .send({ token: 'invalid-token', newPassword: 'ValidPass#123' });

      expect([400, 403]).toContain(response.status);
    });
  });

  describe('POST /api/auth/change-password', () => {
    it('should require authentication', async () => {
      const response = await agent
        .post('/api/auth/change-password')
        .set('csrf-token', csrfToken)
        .send({
          currentPassword: 'OldPass#123',
          newPassword: 'NewPass#123',
          confirmPassword: 'NewPass#123'
        });

      expect([401, 403]).toContain(response.status);
    });
  });
});
