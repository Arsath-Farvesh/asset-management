function isProductionEnvironment() {
  return process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT_NAME === 'production';
}

function normalizeLegacyEnvironmentVariables() {
  if (!process.env.PGUSER && process.env.PGUSERNAME) {
    process.env.PGUSER = process.env.PGUSERNAME;
  }
}

function hasDatabaseConfiguration() {
  if (process.env.DATABASE_URL) {
    return true;
  }

  return Boolean(
    process.env.PGHOST &&
    process.env.PGPORT &&
    process.env.PGUSER &&
    process.env.PGPASSWORD &&
    process.env.PGDATABASE
  );
}

function parseOrigins() {
  return (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function validateEnvironment() {
  normalizeLegacyEnvironmentVariables();

  const errors = [];
  const warnings = [];
  const isProduction = isProductionEnvironment();
  const sessionSecret = process.env.SESSION_SECRET;
  const isSessionSecretWeak = !sessionSecret || sessionSecret === 'change_this_secret' || sessionSecret.length < 32;

  if (!hasDatabaseConfiguration()) {
    errors.push('Database configuration is missing: set DATABASE_URL or complete PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE.');
  }

  if (isSessionSecretWeak) {
    const message = 'SESSION_SECRET is missing or weak. Use a random value with at least 32 characters.';
    if (isProduction) {
      errors.push(message);
    } else {
      warnings.push(message);
    }
  }

  if (isProduction) {
    const corsOrigins = parseOrigins();
    if (corsOrigins.length === 0) {
      warnings.push('CORS_ORIGINS is not set. It is recommended to set allowed origins in production (comma-separated list).');
    }

    if (!process.env.DB_SSL_REJECT_UNAUTHORIZED && !process.env.DATABASE_URL) {
      warnings.push('DB_SSL_REJECT_UNAUTHORIZED is not set. Verify SSL requirements for production database connections.');
    }
  }

  if (process.env.PGUSERNAME && !process.env.PGUSER) {
    warnings.push('PGUSERNAME is deprecated. Prefer PGUSER in environment configuration.');
  }

  return {
    isProduction,
    errors,
    warnings
  };
}

module.exports = {
  validateEnvironment,
  isProductionEnvironment
};
