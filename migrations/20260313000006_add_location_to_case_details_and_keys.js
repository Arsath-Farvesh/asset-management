/**
 * Add location column to case_details and keys tables
 * and backfill from case_type where possible.
 */

const TARGET_TABLES = ['case_details', 'keys'];

exports.up = async function up(knex) {
  for (const tableName of TARGET_TABLES) {
    const hasTable = await knex.schema.hasTable(tableName);
    if (!hasTable) continue;

    const hasLocation = await knex.schema.hasColumn(tableName, 'location');
    if (!hasLocation) {
      await knex.schema.table(tableName, (table) => {
        table.string('location', 255).nullable();
      });
    }

    const hasCaseType = await knex.schema.hasColumn(tableName, 'case_type');
    if (hasCaseType) {
      await knex.raw(
        `UPDATE ??
         SET location = COALESCE(NULLIF(location, ''), case_type)
         WHERE COALESCE(location, '') = ''
           AND COALESCE(case_type, '') <> ''`,
        [tableName]
      );
    }

    await knex.raw(
      `CREATE INDEX IF NOT EXISTS ?? ON ?? (location)`,
      [`${tableName}_location_idx`, tableName]
    );
  }
};

exports.down = async function down(knex) {
  for (const tableName of TARGET_TABLES) {
    const hasTable = await knex.schema.hasTable(tableName);
    if (!hasTable) continue;

    const hasLocation = await knex.schema.hasColumn(tableName, 'location');
    if (hasLocation) {
      await knex.schema.table(tableName, (table) => {
        table.dropColumn('location');
      });
    }
  }
};
