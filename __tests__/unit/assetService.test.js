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

      // createAsset first queries information_schema.columns, then does the INSERT
      pool.query = jest.fn()
        .mockResolvedValueOnce({
          rows: [
            { column_name: 'name', data_type: 'character varying', is_nullable: 'NO', column_default: null },
            { column_name: 'location', data_type: 'character varying', is_nullable: 'NO', column_default: null }
          ]
        })
        .mockResolvedValueOnce({ rows: [mockAsset] });

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

    it('should write an audit log entry on successful creation', async () => {
      const mockAsset = {
        id: 11,
        name: 'Audited Asset',
        location: 'HQ'
      };

      pool.query = jest.fn()
        .mockResolvedValueOnce({
          rows: [
            { column_name: 'name', data_type: 'character varying', is_nullable: 'NO', column_default: null },
            { column_name: 'location', data_type: 'character varying', is_nullable: 'NO', column_default: null }
          ]
        })
        .mockResolvedValueOnce({ rows: [mockAsset] })
        .mockResolvedValueOnce({ rows: [{ id: 999 }] });

      const actor = {
        userId: 5,
        username: 'auditor',
        ipAddress: '127.0.0.1',
        userAgent: 'jest'
      };

      const result = await assetService.createAsset('keys', {
        name: 'Audited Asset',
        location: 'HQ'
      }, actor);

      expect(result.success).toBe(true);
      expect(pool.query).toHaveBeenNthCalledWith(
        3,
        expect.stringContaining('INSERT INTO audit_logs'),
        ['keys', 11, 'CREATE', 5, 'auditor', null, mockAsset, '127.0.0.1', 'jest']
      );
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
      pool.query = jest.fn()
        .mockResolvedValueOnce({ rows: [{ id: 1, name: 'Asset 1' }] })
        .mockResolvedValueOnce({ rows: [{ id: 1001 }] });

      const result = await assetService.deleteAsset('keys', 1);

      expect(result.success).toBe(true);
      expect(result.message).toBe('Asset deleted successfully');
      expect(pool.query).toHaveBeenNthCalledWith(
        2,
        expect.stringContaining('INSERT INTO audit_logs'),
        ['keys', 1, 'DELETE', null, null, { id: 1, name: 'Asset 1' }, null, null, null]
      );
    });

    it('should return error if asset not found', async () => {
      pool.query = jest.fn().mockResolvedValue({ rows: [] });

      const result = await assetService.deleteAsset('keys', 999);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Asset not found');
    });
  });

  describe('updateAsset', () => {
    it('should write an audit log entry on successful update', async () => {
      const oldRow = { id: 3, name: 'Old Name', location: 'A' };
      const updatedRow = { id: 3, name: 'New Name', location: 'B' };

      pool.query = jest.fn()
        .mockResolvedValueOnce({ rows: [{ column_name: 'name' }, { column_name: 'location' }] })
        .mockResolvedValueOnce({ rows: [oldRow] })
        .mockResolvedValueOnce({ rows: [updatedRow] })
        .mockResolvedValueOnce({ rows: [{ id: 2001 }] });

      const actor = {
        userId: 9,
        username: 'admin',
        ipAddress: '10.0.0.1',
        userAgent: 'jest-update'
      };

      const result = await assetService.updateAsset('keys', 3, { name: 'New Name', location: 'B' }, actor);

      expect(result.success).toBe(true);
      expect(pool.query).toHaveBeenNthCalledWith(
        4,
        expect.stringContaining('INSERT INTO audit_logs'),
        ['keys', 3, 'UPDATE', 9, 'admin', oldRow, updatedRow, '10.0.0.1', 'jest-update']
      );
    });
  });

  describe('bulkDeleteAssets', () => {
    it('should write audit log entries for each deleted record', async () => {
      pool.query = jest.fn()
        .mockResolvedValueOnce({ rows: [{ id: 7, name: 'A' }, { id: 8, name: 'B' }] })
        .mockResolvedValueOnce({ rowCount: 2, rows: [{ id: 7 }, { id: 8 }] })
        .mockResolvedValueOnce({ rows: [{ id: 3001 }] })
        .mockResolvedValueOnce({ rows: [{ id: 3002 }] });

      const actor = {
        userId: 4,
        username: 'deleter',
        ipAddress: '10.0.0.2',
        userAgent: 'jest-bulk-delete'
      };

      const result = await assetService.bulkDeleteAssets('keys', [7, 8], actor);

      expect(result.success).toBe(true);
      expect(result.deletedCount).toBe(2);
      expect(pool.query).toHaveBeenNthCalledWith(
        3,
        expect.stringContaining('INSERT INTO audit_logs'),
        ['keys', 7, 'DELETE', 4, 'deleter', { id: 7, name: 'A' }, null, '10.0.0.2', 'jest-bulk-delete']
      );
      expect(pool.query).toHaveBeenNthCalledWith(
        4,
        expect.stringContaining('INSERT INTO audit_logs'),
        ['keys', 8, 'DELETE', 4, 'deleter', { id: 8, name: 'B' }, null, '10.0.0.2', 'jest-bulk-delete']
      );
    });
  });
});
