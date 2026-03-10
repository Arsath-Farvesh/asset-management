/**
 * Fix Keys Table Schema
 * Updates the keys table to match case_details structure for consistency
 */

exports.up = function(knex) {
  // Drop the old keys table
  return knex.schema.dropTable('keys').then(() => {
    // Create new keys table with correct schema matching case_details
    return knex.schema.createTable('keys', table => {
      table.increments('id').primary();
      table.string('name', 255).notNullable();
      table.string('customer_name', 255).notNullable();
      table.string('customer_phone', 20).notNullable();
      table.date('case_date').notNullable();
      table.string('case_number', 100).notNullable();
      table.string('case_type', 100).notNullable();
      table.text('remarks');
      table.timestamps(true, true);
      
      // Indexes for frequently queried fields
      table.index('name');
      table.index('customer_name');
      table.index('case_number');
      table.index('case_date');
    });
  });
};

exports.down = function(knex) {
  // This cannot be easily reverted - would need to restore from backup
  return Promise.resolve();
};
