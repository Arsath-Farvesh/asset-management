const assetService = require('../../src/services/assetService');
const pool = require('../../src/config/database');
const logger = require('../../src/config/logger');

// Mock database pool and logger
jest.mock('../../src/config/database');
jest.mock('../../src/config/logger');

describe('AssetService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Mock logger methods
    logger.error = jest.fn();
    logger.info = jest.fn();
  });

  describe('createAsset', () => {
    it('should successfully create an asset', async () => {
      const mockAsset = {
        id: 1,
        name: 'Test Asset',
        category: 'keys',
        location: 'EJARI'
      };

      pool.query = jest.fn().mockResolvedValue({ rows: [mockAsset] });

      const result = await assetService.createAsset('keys', {
        name: 'Test Asset',
        location: 'EJARI'
      });

      expect(result.success).toBe(true);
      expect(result.data.name).toBe('Test Asset');
    });

    it('should handle errors during asset creation', async () => {
      pool.query = jest.fn().mockRejectedValue(new Error('Database error'));

      const result = await assetService.createAsset('keys', {
        name: 'Test Asset'
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Database error');
    });
  });

  describe('getAssets', () => {
    it('should retrieve all assets from a category', async () => {
      const mockAssets = [
        { id: 1, name: 'Asset 1' },
        { id: 2, name: 'Asset 2' }
      ];

      pool.query = jest.fn().mockResolvedValue({ rows: mockAssets });

      const result = await assetService.getAssets('keys');

      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(2);
    });
  });

  describe('deleteAsset', () => {
    it('should successfully delete an asset', async () => {
      pool.query = jest.fn().mockResolvedValue({ rows: [{ id: 1 }] });

      const result = await assetService.deleteAsset('keys', 1);

      expect(result.success).toBe(true);
      expect(result.message).toBe('Asset deleted successfully');
    });

    it('should return error if asset not found', async () => {
      pool.query = jest.fn().mockResolvedValue({ rows: [] });

      const result = await assetService.deleteAsset('keys', 999);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Asset not found');
    });
  });
});
