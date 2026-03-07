const pool = require('../config/database');
const logger = require('../config/logger');

class AssetService {
  // Create asset
  async createAsset(category, data) {
    try {
      const columns = Object.keys(data).join(', ');
      const values = Object.values(data);
      const placeholders = values.map((_, i) => `$${i + 1}`).join(', ');

      const query = `INSERT INTO ${category} (${columns}) VALUES (${placeholders}) RETURNING *`;
      const result = await pool.query(query, values);

      logger.info(`Asset created in ${category}: ${data.name}`);
      return { success: true, data: result.rows[0] };
    } catch (error) {
      logger.error(`Create asset error in ${category}:`, error);
      return { success: false, error: 'Failed to create asset' };
    }
  }

  // Get all assets from category
  async getAssets(category) {
    try {
      const result = await pool.query(`SELECT * FROM ${category} ORDER BY id DESC`);
      return { success: true, data: result.rows };
    } catch (error) {
      logger.error(`Get assets error from ${category}:`, error);
      return { success: false, error: 'Failed to fetch assets' };
    }
  }

  // Get single asset by ID
  async getAssetById(category, id) {
    try {
      const result = await pool.query(`SELECT * FROM ${category} WHERE id = $1`, [id]);
      
      if (result.rows.length === 0) {
        return { success: false, error: 'Asset not found' };
      }

      return { success: true, data: result.rows[0] };
    } catch (error) {
      logger.error(`Get asset error from ${category}:`, error);
      return { success: false, error: 'Failed to fetch asset' };
    }
  }

  // Update asset
  async updateAsset(category, id, data) {
    try {
      const setClause = Object.keys(data)
        .map((key, i) => `${key} = $${i + 1}`)
        .join(', ');
      const values = [...Object.values(data), id];

      const query = `UPDATE ${category} SET ${setClause} WHERE id = $${values.length} RETURNING *`;
      const result = await pool.query(query, values);

      if (result.rows.length === 0) {
        return { success: false, error: 'Asset not found' };
      }

      logger.info(`Asset updated in ${category}: ID ${id}`);
      return { success: true, data: result.rows[0] };
    } catch (error) {
      logger.error(`Update asset error in ${category}:`, error);
      return { success: false, error: 'Failed to update asset' };
    }
  }

  // Delete asset
  async deleteAsset(category, id) {
    try {
      const result = await pool.query(`DELETE FROM ${category} WHERE id = $1 RETURNING *`, [id]);

      if (result.rows.length === 0) {
        return { success: false, error: 'Asset not found' };
      }

      logger.info(`Asset deleted from ${category}: ID ${id}`);
      return { success: true, message: 'Asset deleted successfully' };
    } catch (error) {
      logger.error(`Delete asset error from ${category}:`, error);
      return { success: false, error: 'Failed to delete asset' };
    }
  }

  // Bulk delete assets
  async bulkDeleteAssets(category, ids) {
    try {
      const placeholders = ids.map((_, i) => `$${i + 1}`).join(', ');
      const query = `DELETE FROM ${category} WHERE id IN (${placeholders}) RETURNING id`;
      const result = await pool.query(query, ids);

      logger.info(`Bulk delete in ${category}: ${result.rowCount} assets deleted`);
      return { success: true, deletedCount: result.rowCount, deletedIds: result.rows.map(r => r.id) };
    } catch (error) {
      logger.error(`Bulk delete error in ${category}:`, error);
      return { success: false, error: 'Failed to delete assets' };
    }
  }

  // Get asset history
  async getHistory() {
    try {
      // This would query an asset_history table if it exists
      // For now, returning a placeholder
      return { success: true, history: [] };
    } catch (error) {
      logger.error('Get history error:', error);
      return { success: false, error: 'Failed to fetch history' };
    }
  }
}

module.exports = new AssetService();
