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

function getTodayDateString() {
  return new Date().toISOString().slice(0, 10);
}

function getFallbackValue(column) {
  const dataType = String(column.data_type || '').toLowerCase();

  if (dataType.includes('date') || dataType.includes('time')) {
    return getTodayDateString();
  }

  if (
    dataType.includes('int') ||
    dataType.includes('numeric') ||
    dataType.includes('decimal') ||
    dataType.includes('real') ||
    dataType.includes('double')
  ) {
    return 0;
  }

  if (dataType.includes('bool')) {
    return false;
  }

  return 'N/A';
}

function addAlias(target, toKey, fromValue) {
  if (fromValue !== undefined && fromValue !== null && fromValue !== '' && target[toKey] === undefined) {
    target[toKey] = fromValue;
  }
}

function normalizePayloadForLegacySchemas(category, payload) {
  const normalized = { ...(payload || {}) };

  // Generic aliases used by mixed/legacy tables
  addAlias(normalized, 'asset_name', normalized.name);
  addAlias(normalized, 'name', normalized.asset_name);
  addAlias(normalized, 'case_name', normalized.name);
  addAlias(normalized, 'name', normalized.case_name);

  addAlias(normalized, 'collection_date', normalized.case_date);
  addAlias(normalized, 'case_date', normalized.collection_date);

  addAlias(normalized, 'key_reference', normalized.case_number);
  addAlias(normalized, 'case_number', normalized.key_reference);

  addAlias(normalized, 'employee_name', normalized.customer_name);
  addAlias(normalized, 'customer_name', normalized.employee_name);

  addAlias(normalized, 'location', normalized.case_type);
  addAlias(normalized, 'case_type', normalized.location);

  addAlias(normalized, 'asset_tag', normalized.serial_number);
  addAlias(normalized, 'serial_number', normalized.asset_tag);

  addAlias(normalized, 'employee_id', normalized.serial_number);
  addAlias(normalized, 'serial_number', normalized.employee_id);

  addAlias(normalized, 'key_reference', normalized.serial_number);
  addAlias(normalized, 'serial_number', normalized.key_reference);

  // Extra handling for legacy keys table shape
  if (category === 'keys') {
    addAlias(normalized, 'case_name', normalized.name);
    addAlias(normalized, 'key_reference', normalized.case_number || normalized.customer_phone);
    addAlias(normalized, 'employee_name', normalized.customer_name);
    addAlias(normalized, 'location', normalized.case_type);
    addAlias(normalized, 'collection_date', normalized.case_date);

    if (!normalized.remarks) {
      const parts = [];
      if (normalized.customer_phone) parts.push(`phone:${normalized.customer_phone}`);
      if (normalized.case_type) parts.push(`type:${normalized.case_type}`);
      if (normalized.case_number) parts.push(`case_no:${normalized.case_number}`);
      normalized.remarks = parts.join(' | ') || undefined;
    }
  }

  return normalized;
}

function normalizeRecordForLegacySchemas(record) {
  const normalized = { ...(record || {}) };

  if ((normalized.location === undefined || normalized.location === null || normalized.location === '') && normalized.case_type) {
    normalized.location = normalized.case_type;
  }

  if ((normalized.serial_number === undefined || normalized.serial_number === null || normalized.serial_number === '')) {
    normalized.serial_number = normalized.asset_tag || normalized.employee_id || normalized.key_reference || normalized.serial_number;
  }

  return normalized;
}

class AssetService {
  async writeAuditLog({ tableName, recordId, action, actor, oldData = null, newData = null }) {
    try {
      await pool.query(
        `INSERT INTO audit_logs (table_name, record_id, action, user_id, username, old_data, new_data, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          tableName,
          recordId,
          action,
          actor?.userId || null,
          actor?.username || null,
          oldData,
          newData,
          actor?.ipAddress || null,
          actor?.userAgent || null
        ]
      );
    } catch (auditError) {
      logger.warn('Audit log write skipped', {
        table: tableName,
        recordId,
        action,
        error: auditError.message
      });
    }
  }

  // Create asset
  async createAsset(category, data, actor = null) {
    try {
      if (!validateCategory(category)) {
        return { success: false, error: 'Invalid asset category' };
      }

      const normalizedData = normalizePayloadForLegacySchemas(category, data);

      const colResult = await pool.query(
        `SELECT column_name, data_type, is_nullable, column_default
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1`,
        [category]
      );

      if (!colResult.rows || colResult.rows.length === 0) {
        return { success: false, error: `Table not found or has no columns: ${category}` };
      }

      const tableColumns = colResult.rows;
      const entries = [];

      tableColumns.forEach((column) => {
        const key = column.column_name;
        if (key === 'id') {
          return;
        }

        const incoming = normalizedData[key];
        if (incoming !== undefined) {
          entries.push([key, incoming]);
          return;
        }

        const isRequired = column.is_nullable === 'NO' && !column.column_default;
        if (isRequired) {
          entries.push([key, getFallbackValue(column)]);
        }
      });

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
      const createdRecord = result.rows[0];

      await this.writeAuditLog({
        tableName: category,
        recordId: createdRecord.id,
        action: 'CREATE',
        actor,
        oldData: null,
        newData: createdRecord
      });

      logger.info(`Asset created in ${category}: ${data.name || data.asset_name || data.case_name || 'unknown'}`);
      return { success: true, data: createdRecord };
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
      return { success: true, data: result.rows.map(normalizeRecordForLegacySchemas) };
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

      return { success: true, data: normalizeRecordForLegacySchemas(result.rows[0]) };
    } catch (error) {
      logger.error(`Get asset error from ${category}:`, error);
      return { success: false, error: 'Failed to fetch asset' };
    }
  }

  // Update asset
  async updateAsset(category, id, data, actor = null) {
    try {
      if (!validateCategory(category)) {
        return { success: false, error: 'Invalid asset category' };
      }

      const normalizedId = normalizeId(id);
      if (!normalizedId) {
        return { success: false, error: 'Invalid asset id' };
      }

      const normalizedData = normalizePayloadForLegacySchemas(category, data);
      const colResult = await pool.query(
        `SELECT column_name
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1`,
        [category]
      );

      if (!colResult.rows || colResult.rows.length === 0) {
        return { success: false, error: `Table not found or has no columns: ${category}` };
      }

      const existingColumns = new Set(colResult.rows.map((row) => row.column_name));

      const entries = Object.entries(normalizedData || {}).filter(([key, value]) => (
        value !== undefined && key !== 'id' && existingColumns.has(key)
      ));

      if (entries.length === 0) {
        return { success: false, error: 'No valid fields to update' };
      }

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
      const previousStateResult = await pool.query(`SELECT * FROM ${category} WHERE id = $1`, [normalizedId]);
      const previousState = previousStateResult.rows[0] || null;
      const result = await pool.query(query, queryValues);

      if (result.rows.length === 0) {
        return { success: false, error: 'Asset not found' };
      }

      await this.writeAuditLog({
        tableName: category,
        recordId: normalizedId,
        action: 'UPDATE',
        actor,
        oldData: previousState,
        newData: result.rows[0]
      });

      logger.info(`Asset updated in ${category}: ID ${normalizedId}`);
      return { success: true, data: result.rows[0] };
    } catch (error) {
      logger.error(`Update asset error in ${category}:`, error);
      return { success: false, error: 'Failed to update asset' };
    }
  }

  // Delete asset
  async deleteAsset(category, id, actor = null) {
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

      await this.writeAuditLog({
        tableName: category,
        recordId: normalizedId,
        action: 'DELETE',
        actor,
        oldData: result.rows[0],
        newData: null
      });

      logger.info(`Asset deleted from ${category}: ID ${normalizedId}`);
      return { success: true, message: 'Asset deleted successfully' };
    } catch (error) {
      logger.error(`Delete asset error from ${category}:`, error);
      return { success: false, error: 'Failed to delete asset' };
    }
  }

  // Bulk delete assets
  async bulkDeleteAssets(category, ids, actor = null) {
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

      const existingRowsResult = await pool.query(
        `SELECT * FROM ${category} WHERE id = ANY($1::int[])`,
        [normalizedIds]
      );
      const existingRowsById = new Map(existingRowsResult.rows.map((row) => [row.id, row]));

      const placeholders = normalizedIds.map((_, i) => `$${i + 1}`).join(', ');
      const query = `DELETE FROM ${category} WHERE id IN (${placeholders}) RETURNING id`;
      const result = await pool.query(query, normalizedIds);

      for (const deleted of result.rows) {
        await this.writeAuditLog({
          tableName: category,
          recordId: deleted.id,
          action: 'DELETE',
          actor,
          oldData: existingRowsById.get(deleted.id) || null,
          newData: null
        });
      }

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

          const serialExpr = cols.has('serial_number')
            ? 'serial_number'
            : cols.has('asset_tag')
            ? 'asset_tag'
            : cols.has('employee_id')
            ? 'employee_id'
            : cols.has('key_reference')
            ? 'key_reference'
            : 'NULL';
          const employeeExpr = cols.has('employee_name') ? 'employee_name' : 'NULL';
          const locationExpr = cols.has('location') ? 'location' : cols.has('case_type') ? 'case_type' : 'NULL';
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
