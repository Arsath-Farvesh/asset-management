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
    it('should retrieve assets for a category', async () => {
      const mockAssets = [
        { id: 1, name: 'Asset 1' },
        { id: 2, name: 'Asset 2' }
      ];

      pool.query = jest.fn().mockResolvedValue({ rows: mockAssets });

      const response = await agent
        .get('/api/assets/keys');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });

  describe('POST /api/assets/:category', () => {
    it('should require authentication', async () => {
      const response = await agent
        .post('/api/assets/keys')
        .set('CSRF-Token', csrfToken)
        .send({ name: 'Test Asset' });

      expect(response.status).toBe(401);
    });
  });

  describe('DELETE /api/assets/:category/:id', () => {
    it('should require authentication', async () => {
      const response = await agent
        .delete('/api/assets/keys/1')
        .set('CSRF-Token', csrfToken);

      expect(response.status).toBe(401);
    });
  });
});
