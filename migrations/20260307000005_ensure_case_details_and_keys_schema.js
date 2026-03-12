/**
 * Idempotent migration to ensure case_details and keys tables
 * have the correct schema regardless of whether migrations 3 and 4 ran.
 *
 * Safe to run multiple times — all operations check existence first.
 */

exports.up = async function (knex) {
  // ── 1. Ensure case_details table exists ──────────────────────────────
  const hasCaseDetails = await knex.schema.hasTable('case_details');
  if (!hasCaseDetails) {
    await knex.schema.createTable('case_details', (table) => {
      table.increments('id').primary();
      table.string('name', 255).notNullable();
      table.string('customer_name', 255).notNullable();
      table.string('customer_phone', 20).notNullable();
      table.date('case_date').notNullable();
      table.string('case_number', 100).notNullable();
      table.string('case_type', 100).notNullable();
      table.text('remarks');
      table.timestamps(true, true);

      table.index('name');
      table.index('customer_name');
      table.index('case_number');
      table.index('case_date');
    });
  }

  // ── 2. Fix keys table schema ─────────────────────────────────────────
  const hasKeysTable = await knex.schema.hasTable('keys');

  if (!hasKeysTable) {
    // No table at all — create fresh
    await knex.schema.createTable('keys', (table) => {
      table.increments('id').primary();
      table.string('name', 255).notNullable();
      table.string('customer_name', 255).notNullable();
      table.string('customer_phone', 20).notNullable();
      table.date('case_date').notNullable();
      table.string('case_number', 100).notNullable();
      table.string('case_type', 100).notNullable();
      table.text('remarks');
      table.timestamps(true, true);

      table.index('name');
      table.index('customer_name');
      table.index('case_number');
      table.index('case_date');
    });
    return;
  }

  // Table exists — check whether it has the new schema (column 'name')
  const hasNameCol = await knex.schema.hasColumn('keys', 'name');
  if (!hasNameCol) {
    // Old schema detected (has case_name / key_reference / etc.)
    // Drop the old table and recreate with the new schema.
    // The old data used different column semantics and cannot be migrated 1-to-1.
    await knex.schema.dropTable('keys');
    await knex.schema.createTable('keys', (table) => {
      table.increments('id').primary();
      table.string('name', 255).notNullable();
      table.string('customer_name', 255).notNullable();
      table.string('customer_phone', 20).notNullable();
      table.date('case_date').notNullable();
      table.string('case_number', 100).notNullable();
      table.string('case_type', 100).notNullable();
      table.text('remarks');
      table.timestamps(true, true);

      table.index('name');
      table.index('customer_name');
      table.index('case_number');
      table.index('case_date');
    });
  }
  // If hasNameCol is true, keys already has the correct schema — nothing to do.
};

exports.down = async function () {
  // Intentionally left empty — this migration resolves schema drift
  // and cannot be meaningfully reversed without knowing the prior state.
  return Promise.resolve();
};
