const request = require('supertest');
const app = require('../../server');
const pool = require('../../src/config/database');

// Mock database
jest.mock('../../src/config/database');

describe('Asset Routes Integration Tests', () => {
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

  describe('GET /api/assets/:category', () => {
    it('should require authentication', async () => {
      const response = await agent
        .get('/api/assets/keys');

      expect(response.status).toBe(401);
    });
  });

  describe('POST /api/assets/:category', () => {
    it('should require authentication', async () => {
      const response = await agent
        .post('/api/assets/keys')
        .set('csrf-token', csrfToken)
        .send({ name: 'Test Asset' });

      expect([401, 403]).toContain(response.status);
    });
  });

  describe('DELETE /api/assets/:category/:id', () => {
    it('should require authentication', async () => {
      const response = await agent
        .delete('/api/assets/keys/1')
        .set('csrf-token', csrfToken);

      expect([401, 403]).toContain(response.status);
    });
  });
});
