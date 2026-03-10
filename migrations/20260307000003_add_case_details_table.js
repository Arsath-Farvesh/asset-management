/**
 * Add Case Details Table
 * Creates the case_details table for managing case information
 */

exports.up = function(knex) {
  return knex.schema.createTable('case_details', table => {
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
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists('case_details');
};
