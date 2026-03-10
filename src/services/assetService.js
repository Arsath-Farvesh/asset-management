const pool = require('../config/database');
const logger = require('../config/logger');

const DEFAULT_ALLOWED_CATEGORIES = [
  'assets',
  'case_details',
  'depreciation_history',
  'digital_media',
  'documents',
  'employees',
  'keys',
  'financial_assets',
  'furniture',
  'infrastructure',
  'intellectual_property',
  'it_hardware',
  'leased_assets',
  'locations',
  'machinery_equipment',
  'maintenance_logs',
  'real_estate',
  'software_license',
  'tools',
  'vehicles',
  'equipments_assets',
  'laptops',
  'monitors',
  'accessories',
  'id_cards'
];

const CATEGORY_IDENTIFIER_REGEX = /^[a-z_][a-z0-9_]*$/;
const COLUMN_IDENTIFIER_REGEX = /^[a-z_][a-z0-9_]*$/;

const allowedCategorySet = new Set(
  [
    ...DEFAULT_ALLOWED_CATEGORIES,
    ...(process.env.ASSET_TABLES || '')
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)
  ]
);

function validateCategory(category) {
  return (
    typeof category === 'string' &&
    CATEGORY_IDENTIFIER_REGEX.test(category) &&
    allowedCategorySet.has(category)
  );
}

function validateColumns(columns) {
  return Array.isArray(columns) && columns.length > 0 && columns.every((column) => COLUMN_IDENTIFIER_REGEX.test(column));
}

function normalizeId(id) {
  const parsed = Number.parseInt(id, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

class AssetService {
  // Create asset
  async createAsset(category, data) {
    try {
      if (!validateCategory(category)) {
        return { success: false, error: 'Invalid asset category' };
      }

      const entries = Object.entries(data || {}).filter(([, value]) => value !== undefined);
      const columnsArray = entries.map(([key]) => key);
      const values = entries.map(([, value]) => value);

      if (!validateColumns(columnsArray)) {
        return { success: false, error: 'Invalid asset payload' };
      }

      const columns = columnsArray.join(', ');
      const placeholders = values.map((_, i) => `$${i + 1}`).join(', ');

      const query = `INSERT INTO ${category} (${columns}) VALUES (${placeholders}) RETURNING *`;
      logger.info(`Executing INSERT for ${category}:`, { columns, query: query.substring(0, 100) });
      const result = await pool.query(query, values);

      logger.info(`Asset created in ${category}: ${data.name || data.asset_name || data.case_name || 'unknown'}`);
      return { success: true, data: result.rows[0] };
    } catch (error) {
      logger.error(`Create asset error in ${category}:`, {
        message: error.message,
        code: error.code,
        detail: error.detail,
        table: category
      });
      return { success: false, error: error.message || 'Failed to create asset' };
    }
  }

  // Get all assets from category
  async getAssets(category) {
    try {
      if (!validateCategory(category)) {
        return { success: false, error: 'Invalid asset category' };
      }

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
      if (!validateCategory(category)) {
        return { success: false, error: 'Invalid asset category' };
      }

      const normalizedId = normalizeId(id);
      if (!normalizedId) {
        return { success: false, error: 'Invalid asset id' };
      }

      const result = await pool.query(`SELECT * FROM ${category} WHERE id = $1`, [normalizedId]);
      
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
      if (!validateCategory(category)) {
        return { success: false, error: 'Invalid asset category' };
      }

      const normalizedId = normalizeId(id);
      if (!normalizedId) {
        return { success: false, error: 'Invalid asset id' };
      }

      const entries = Object.entries(data || {}).filter(([, value]) => value !== undefined);
      const columnsArray = entries.map(([key]) => key);
      const values = entries.map(([, value]) => value);

      if (!validateColumns(columnsArray)) {
        return { success: false, error: 'Invalid asset payload' };
      }

      const setClause = columnsArray
        .map((key, i) => `${key} = $${i + 1}`)
        .join(', ');
      const queryValues = [...values, normalizedId];

      const query = `UPDATE ${category} SET ${setClause} WHERE id = $${queryValues.length} RETURNING *`;
      const result = await pool.query(query, queryValues);

      if (result.rows.length === 0) {
        return { success: false, error: 'Asset not found' };
      }

      logger.info(`Asset updated in ${category}: ID ${normalizedId}`);
      return { success: true, data: result.rows[0] };
    } catch (error) {
      logger.error(`Update asset error in ${category}:`, error);
      return { success: false, error: 'Failed to update asset' };
    }
  }

  // Delete asset
  async deleteAsset(category, id) {
    try {
      if (!validateCategory(category)) {
        return { success: false, error: 'Invalid asset category' };
      }

      const normalizedId = normalizeId(id);
      if (!normalizedId) {
        return { success: false, error: 'Invalid asset id' };
      }

      const result = await pool.query(`DELETE FROM ${category} WHERE id = $1 RETURNING *`, [normalizedId]);

      if (result.rows.length === 0) {
        return { success: false, error: 'Asset not found' };
      }

      logger.info(`Asset deleted from ${category}: ID ${normalizedId}`);
      return { success: true, message: 'Asset deleted successfully' };
    } catch (error) {
      logger.error(`Delete asset error from ${category}:`, error);
      return { success: false, error: 'Failed to delete asset' };
    }
  }

  // Bulk delete assets
  async bulkDeleteAssets(category, ids) {
    try {
      if (!validateCategory(category)) {
        return { success: false, error: 'Invalid asset category' };
      }

      const normalizedIds = (ids || [])
        .map((id) => normalizeId(id))
        .filter(Boolean);

      if (normalizedIds.length === 0) {
        return { success: false, error: 'No valid asset IDs provided' };
      }

      const placeholders = normalizedIds.map((_, i) => `$${i + 1}`).join(', ');
      const query = `DELETE FROM ${category} WHERE id IN (${placeholders}) RETURNING id`;
      const result = await pool.query(query, normalizedIds);

      logger.info(`Bulk delete in ${category}: ${result.rowCount} assets deleted`);
      return { success: true, deletedCount: result.rowCount, deletedIds: result.rows.map(r => r.id) };
    } catch (error) {
      logger.error(`Bulk delete error in ${category}:`, error);
      return { success: false, error: 'Failed to delete assets' };
    }
  }

  // Get asset history — queries all existing category tables
  async getHistory() {
    try {
      // Find which category tables actually exist in the DB
      const tablesResult = await pool.query(
        `SELECT table_name FROM information_schema.tables
         WHERE table_schema = 'public'
           AND table_type = 'BASE TABLE'
           AND table_name = ANY($1)`,
        [Array.from(allowedCategorySet)]
      );

      const existingTables = tablesResult.rows.map((r) => r.table_name);
      const allRows = [];

      for (const table of existingTables) {
        try {
          // Discover columns for this table
          const colResult = await pool.query(
            `SELECT column_name FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = $1`,
            [table]
          );
          const cols = new Set(colResult.rows.map((r) => r.column_name));

          // Normalise name column across different table schemas
          const nameExpr = cols.has('name')
            ? 'name'
            : cols.has('asset_name')
            ? 'asset_name'
            : cols.has('case_name')
            ? 'case_name'
            : 'NULL';

          const serialExpr = cols.has('serial_number') ? 'serial_number' : 'NULL';
          const employeeExpr = cols.has('employee_name') ? 'employee_name' : 'NULL';
          const locationExpr = cols.has('location') ? 'location' : 'NULL';
          const submittedByExpr = cols.has('submitted_by') ? 'submitted_by' : 'NULL';
          const createdAtExpr = cols.has('created_at') ? 'created_at' : 'NOW()';

          const result = await pool.query(
            `SELECT id,
                    ${nameExpr}        AS name,
                    ${serialExpr}      AS serial_number,
                    ${employeeExpr}    AS employee_name,
                    ${locationExpr}    AS location,
                    ${submittedByExpr} AS submitted_by,
                    ${createdAtExpr}   AS created_at
             FROM ${table}
             ORDER BY ${createdAtExpr} DESC
             LIMIT 500`
          );

          result.rows.forEach((row) => allRows.push({ ...row, category: table }));
        } catch (tableError) {
          logger.warn(`History: skipping table ${table}: ${tableError.message}`);
        }
      }

      // Sort combined results newest-first
      allRows.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

      return { success: true, data: allRows };
    } catch (error) {
      logger.error('Get history error:', error);
      return { success: false, error: 'Failed to fetch history' };
    }
  }
}

module.exports = new AssetService();
