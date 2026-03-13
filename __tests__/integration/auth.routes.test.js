const request = require('supertest');
const app = require('../../server');
const pool = require('../../src/config/database');

// Mock database
jest.mock('../../src/config/database');

describe('Auth Routes Integration Tests', () => {
  let csrfToken;
  let agent;

  beforeEach(async () => {
    jest.clearAllMocks();
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
});
