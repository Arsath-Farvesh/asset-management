/**
 * Migration: Add submitted_by tracking to all asset tables
 * and extended profile fields to users table.
 */

const ASSET_TABLES = [
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

exports.up = async function (knex) {
  // Add submitted_by to every asset category table (skip if already present)
  for (const table of ASSET_TABLES) {
    const exists = await knex.schema.hasTable(table);
    if (!exists) continue;

    const hasCol = await knex.schema.hasColumn(table, 'submitted_by');
    if (!hasCol) {
      await knex.schema.table(table, (t) => {
        t.string('submitted_by', 100).nullable();
      });
    }
  }

  // Add extended profile fields to users table
  const hasFirstName = await knex.schema.hasColumn('users', 'first_name');
  if (!hasFirstName) {
    await knex.schema.table('users', (t) => {
      t.string('first_name', 100).nullable();
      t.string('last_name', 100).nullable();
      t.string('office_location', 150).nullable();
      t.string('phone', 50).nullable();
    });
  }
};

exports.down = async function (knex) {
  for (const table of ASSET_TABLES) {
    const exists = await knex.schema.hasTable(table);
    if (!exists) continue;
    const hasCol = await knex.schema.hasColumn(table, 'submitted_by');
    if (hasCol) {
      await knex.schema.table(table, (t) => t.dropColumn('submitted_by'));
    }
  }

  const hasFirstName = await knex.schema.hasColumn('users', 'first_name');
  if (hasFirstName) {
    await knex.schema.table('users', (t) => {
      t.dropColumn('first_name');
      t.dropColumn('last_name');
      t.dropColumn('office_location');
      t.dropColumn('phone');
    });
  }
};
