require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  connectionTimeoutMillis: 30000,
  idleTimeoutMillis: 30000,
  max: 20,
  ssl: { rejectUnauthorized: false }
});

async function addColumns() {
  const client = await pool.connect();
  try {
    console.log('🔗 Connected to database');
    
    // Add columns for employees table
    console.log('Adding columns to employees table...');
    await client.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS department TEXT`);
    await client.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS position TEXT`);
    console.log('✅ employees table updated');
    
    // Add columns for assets table
    console.log('Adding columns to assets table...');
    await client.query(`ALTER TABLE assets ADD COLUMN IF NOT EXISTS purchase_date DATE`);
    await client.query(`ALTER TABLE assets ADD COLUMN IF NOT EXISTS value NUMERIC`);
    console.log('✅ assets table updated');
    
    // Add columns for maintenance_logs table
    console.log('Adding columns to maintenance_logs table...');
    await client.query(`ALTER TABLE maintenance_logs ADD COLUMN IF NOT EXISTS maintenance_date DATE`);
    await client.query(`ALTER TABLE maintenance_logs ADD COLUMN IF NOT EXISTS technician TEXT`);
    console.log('✅ maintenance_logs table updated');
    
    // Add columns for it_hardware table
    console.log('Adding columns to it_hardware table...');
    await client.query(`ALTER TABLE it_hardware ADD COLUMN IF NOT EXISTS brand TEXT`);
    await client.query(`ALTER TABLE it_hardware ADD COLUMN IF NOT EXISTS model TEXT`);
    console.log('✅ it_hardware table updated');
    
    // Add columns for vehicles table
    console.log('Adding columns to vehicles table...');
    await client.query(`ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS make TEXT`);
    await client.query(`ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS model TEXT`);
    await client.query(`ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS year INTEGER`);
    console.log('✅ vehicles table updated');
    
    console.log('\n✅ All columns added successfully!');
  } catch (err) {
    console.error('❌ Error:', err.message);
  } finally {
    client.release();
    await pool.end();
  }
}

addColumns();
