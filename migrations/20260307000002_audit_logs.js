/**
 * Audit Logs Table
 * Tracks all changes to assets for compliance and history
 */

exports.up = function(knex) {
  return knex.schema.createTable('audit_logs', table => {
    table.increments('id').primary();
    table.string('table_name', 100).notNullable();
    table.integer('record_id').notNullable();
    table.string('action', 50).notNullable(); // 'CREATE', 'UPDATE', 'DELETE'
    table.integer('user_id').references('id').inTable('users').onDelete('SET NULL');
    table.string('username', 100);
    table.jsonb('old_data');
    table.jsonb('new_data');
    table.string('ip_address', 45);
    table.string('user_agent', 500);
    table.timestamp('created_at').defaultTo(knex.fn.now());
    
    // Indexes for efficient querying
    table.index('table_name');
    table.index('record_id');
    table.index('action');
    table.index('user_id');
    table.index('created_at');
    table.index(['table_name', 'record_id']); // Composite index for record history
  });
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists('audit_logs');
};
