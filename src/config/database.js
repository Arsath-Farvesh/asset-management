const { Pool } = require('pg');
const logger = require('./logger');

// Database configuration
const dbUrl = process.env.DATABASE_URL;

const sslConfig = process.env.DB_SSL_REJECT_UNAUTHORIZED === 'false' 
  ? { rejectUnauthorized: false } 
  : undefined;

const poolConfig = {
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
};

// Use DATABASE_URL if available, otherwise pg will use PG* env vars
if (dbUrl) {
  poolConfig.connectionString = dbUrl;
  poolConfig.ssl = sslConfig;
  logger.info('🔗 Using DATABASE_URL for connection');
} else {
  // Using individual PG* variables (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE)
  poolConfig.ssl = sslConfig;
  logger.info('🔗 Using PG* environment variables for connection');
  logger.info(`   Host: ${process.env.PGHOST}:${process.env.PGPORT}`);
  logger.info(`   SSL: ${sslConfig ? 'enabled' : 'disabled'}`);
}

const pool = new Pool(poolConfig);

// Test database connection
pool.on('connect', () => {
  logger.debug('Database client connected');
});

pool.on('error', (err) => {
  logger.error('Unexpected database error:', err);
});

module.exports = pool;
