const DEFAULT_BODY_LIMIT = '32kb';
const DEFAULT_MAX_INPUT_CHARS = 32000;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60000;
const DEFAULT_RATE_LIMIT_MAX = 60;

function parsePositiveInteger(value, name, fallback, maximum) {
  if (value === undefined || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return parsed;
}

function parseBodyLimit(value) {
  if (value === undefined || value === '') return DEFAULT_BODY_LIMIT;
  if (!/^\d+(?:kb|mb)$/i.test(value)) {
    throw new Error('JSON_BODY_LIMIT must be a positive size such as 32kb or 1mb');
  }
  const amount = Number.parseInt(value, 10);
  const unit = value.slice(String(amount).length).toLowerCase();
  const bytes = amount * (unit === 'mb' ? 1024 * 1024 : 1024);
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > 1024 * 1024) {
    throw new Error('JSON_BODY_LIMIT must not exceed 1mb');
  }
  return value.toLowerCase();
}

function parseOrigins(value, nodeEnv) {
  const rawOrigins = value === undefined
    ? (nodeEnv === 'production' ? '' : 'http://localhost:3000')
    : value;
  if (!rawOrigins.trim()) {
    if (nodeEnv === 'production') {
      throw new Error('CORS_ORIGINS must contain at least one origin in production');
    }
    return [];
  }

  const origins = rawOrigins.split(',').map((origin) => origin.trim());
  for (const origin of origins) {
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      throw new Error('CORS_ORIGINS must be a comma-separated list of valid origins');
    }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== origin) {
      throw new Error('CORS_ORIGINS entries must be HTTP(S) origins without paths');
    }
  }
  return [...new Set(origins)];
}

function loadConfig(env) {
  const nodeEnv = env.NODE_ENV || 'development';
  if (!['development', 'test', 'production'].includes(nodeEnv)) {
    throw new Error('NODE_ENV must be development, test, or production');
  }

  const port = parsePositiveInteger(env.PORT, 'PORT', 3000, 65535);
  const maxInputChars = parsePositiveInteger(
    env.MAX_INPUT_CHARS,
    'MAX_INPUT_CHARS',
    DEFAULT_MAX_INPUT_CHARS,
    1024 * 1024
  );
  const rateLimitWindowMs = parsePositiveInteger(
    env.RATE_LIMIT_WINDOW_MS,
    'RATE_LIMIT_WINDOW_MS',
    DEFAULT_RATE_LIMIT_WINDOW_MS,
    24 * 60 * 60 * 1000
  );
  const rateLimitMax = parsePositiveInteger(
    env.RATE_LIMIT_MAX,
    'RATE_LIMIT_MAX',
    DEFAULT_RATE_LIMIT_MAX,
    10000
  );
  const logLevel = env.LOG_LEVEL || 'info';
  if (!['fatal', 'error', 'warn', 'info', 'debug'].includes(logLevel)) {
    throw new Error('LOG_LEVEL must be fatal, error, warn, info, or debug');
  }

  const featherlessApiKey = (env.FEATHERLESS_API_KEY || '').trim();
  const featherlessModel = (env.FEATHERLESS_MODEL || 'Qwen/Qwen2.5-7B-Instruct').trim();

  return Object.freeze({
    nodeEnv,
    port,
    corsOrigins: parseOrigins(env.CORS_ORIGINS, nodeEnv),
    jsonBodyLimit: parseBodyLimit(env.JSON_BODY_LIMIT),
    maxInputChars,
    rateLimitWindowMs,
    rateLimitMax,
    logLevel,
    featherlessApiKey,
    featherlessModel
  });
}

module.exports = { loadConfig };
