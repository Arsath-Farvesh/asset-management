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

function isRetryableDbError(error) {
  if (!error) {
    return false;
  }

  const retryableCodes = new Set([
    '57P03', // the database system is starting up
    '53300', // too many connections
    '08000',
    '08003',
    '08006',
    '08001'
  ]);

  if (error.code && retryableCodes.has(error.code)) {
    return true;
  }

  const retryableMessages = [
    'the database system is starting up',
    'Connection terminated unexpectedly',
    'ECONNRESET',
    'ETIMEDOUT'
  ];

  const message = String(error.message || '');
  return retryableMessages.some((text) => message.includes(text));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const baseQuery = pool.query.bind(pool);

pool.query = async (...args) => {
  const maxAttempts = Number.parseInt(process.env.DB_QUERY_RETRY_ATTEMPTS || '4', 10);
  const baseDelayMs = Number.parseInt(process.env.DB_QUERY_RETRY_DELAY_MS || '350', 10);

  let lastError;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await baseQuery(...args);
    } catch (error) {
      lastError = error;

      if (!isRetryableDbError(error) || attempt === maxAttempts) {
        throw error;
      }

      const delay = baseDelayMs * attempt;
      logger.warn(`Retrying database query after transient error (attempt ${attempt}/${maxAttempts})`, {
        code: error.code,
        message: error.message,
        delayMs: delay
      });
      await sleep(delay);
    }
  }

  throw lastError;
};

// Test database connection
pool.on('connect', () => {
  logger.debug('Database client connected');
});

pool.on('error', (err) => {
  logger.error('Unexpected database error:', err);
});

module.exports = pool;
