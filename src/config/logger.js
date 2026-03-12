const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const SENSITIVE_KEYWORDS = ['password', 'pass', 'token', 'secret', 'apiKey', 'apikey', 'authorization', 'cookie', 'session'];

function sanitizeString(value) {
  if (typeof value !== 'string') {
    return value;
  }

  return value
    .replace(/(password|pass|token|secret|api[_-]?key|authorization|cookie|session)\s*[:=]\s*([^\s,;]+)/gi, '$1=[REDACTED]')
    .replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED]');
}

function sanitizeObject(value) {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeObject(item));
  }

  if (value && typeof value === 'object') {
    const output = {};

    Object.keys(value).forEach((key) => {
      const lowerKey = key.toLowerCase();
      const isSensitive = SENSITIVE_KEYWORDS.some((keyword) => lowerKey.includes(keyword.toLowerCase()));

      if (isSensitive) {
        output[key] = '[REDACTED]';
      } else {
        output[key] = sanitizeObject(value[key]);
      }
    });

    return output;
  }

  return sanitizeString(value);
}

const redactSensitiveData = winston.format((info) => {
  const sanitized = sanitizeObject(info);

  if (sanitized.message) {
    sanitized.message = sanitizeString(sanitized.message);
  }

  return sanitized;
});

// Logging configuration
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  redactSensitiveData(),
  winston.format.json()
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  transports: [
    new DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxSize: '20m',
      maxFiles: '14d'
    }),
    new DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d'
    })
  ]
});

// Console logging in development only
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// Backward compatibility alias without overriding Winston's internal logger.log() method.
logger.legacy = {
  info: (msg, ...meta) => logger.info(msg, ...meta),
  error: (msg, ...meta) => logger.error(msg, ...meta),
  warn: (msg, ...meta) => logger.warn(msg, ...meta),
  debug: (msg, ...meta) => logger.debug(msg, ...meta)
};

module.exports = logger;
