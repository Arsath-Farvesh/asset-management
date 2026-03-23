/**
 * Initial Database Schema
 * Creates all core tables for asset management system
 */

exports.up = function(knex) {
  return knex.schema
    // Users table
    .createTable('users', table => {
      table.increments('id').primary();
      table.string('username', 100).notNullable().unique();
      table.string('email', 255).notNullable().unique();
      table.string('password', 255).notNullable();
      table.string('role', 50).notNullable().defaultTo('user');
      table.string('department', 100);
      table.string('oauth_provider', 50);
      table.string('oauth_id', 255);
      table.timestamps(true, true);
      
      // Indexes
      table.index('username');
      table.index('email');
      table.index('role');
    })
    
    // Keys table
    .createTable('keys', table => {
      table.increments('id').primary();
      table.string('case_name', 255).notNullable();
      table.string('key_reference', 255).notNullable();
      table.string('location', 255).notNullable();
      table.string('employee_name', 255).notNullable();
      table.date('collection_date').notNullable();
      table.text('remarks');
      table.timestamps(true, true);
      
      // Indexes frequency queried fields
      table.index('case_name');
      table.index('location');
      table.index('employee_name');
      table.index('collection_date');
    })
    
    // Laptops table
    .createTable('laptops', table => {
      table.increments('id').primary();
      table.string('asset_name', 255).notNullable();
      table.string('asset_tag', 100).notNullable().unique();
      table.string('location', 255).notNullable();
      table.string('employee_name', 255).notNullable();
      table.date('collection_date').notNullable();
      table.text('remarks');
      table.timestamps(true, true);
      
      table.index('asset_name');
      table.index('asset_tag');
      table.index('location');
      table.index('employee_name');
    })
    
    // Monitors table
    .createTable('monitors', table => {
      table.increments('id').primary();
      table.string('asset_name', 255).notNullable();
      table.string('asset_tag', 100).notNullable().unique();
      table.string('location', 255).notNullable();
      table.string('employee_name', 255).notNullable();
      table.date('collection_date').notNullable();
      table.text('remarks');
      table.timestamps(true, true);
      
      table.index('asset_tag');
      table.index('location');
      table.index('employee_name');
    })
    
    // Accessories table
    .createTable('accessories', table => {
      table.increments('id').primary();
      table.string('asset_name', 255).notNullable();
      table.string('asset_tag', 100);
      table.string('location', 255).notNullable();
      table.string('employee_name', 255).notNullable();
      table.date('collection_date').notNullable();
      table.text('remarks');
      table.timestamps(true, true);
      
      table.index('asset_name');
      table.index('location');
      table.index('employee_name');
    })
    
    // ID Cards table
    .createTable('id_cards', table => {
      table.increments('id').primary();
      table.string('asset_name', 255).notNullable();
      table.string('employee_id', 100).notNullable();
      table.string('location', 255).notNullable();
      table.string('employee_name', 255).notNullable();
      table.date('collection_date').notNullable();
      table.text('remarks');
      table.timestamps(true, true);
      
      table.index('employee_id');
      table.index('employee_name');
      table.index('location');
    });
};

exports.down = function(knex) {
  return knex.schema
    .dropTableIfExists('id_cards')
    .dropTableIfExists('accessories')
    .dropTableIfExists('monitors')
    .dropTableIfExists('laptops')
    .dropTableIfExists('keys')
    .dropTableIfExists('users');
};
