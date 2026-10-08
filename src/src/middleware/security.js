const cors = require('cors');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { AppError } = require('../errors');

function securityMiddleware(config) {
  const corsMiddleware = cors({
    credentials: false,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Request-Id'],
    origin(origin, callback) {
      if (!origin || config.corsOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new AppError('Origin is not allowed', 403, 'CORS_ORIGIN_DENIED'));
    }
  });

  const limiter = rateLimit({
    windowMs: config.rateLimitWindowMs,
    limit: config.rateLimitMax,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skip: (req) => req.path === '/health',
    handler(req, res) {
      res.status(429).json({
        success: false,
        error: { code: 'RATE_LIMITED', message: 'Too many requests' },
        requestId: req.requestId
      });
    }
  });

  return { helmetMiddleware: helmet(), corsMiddleware, limiter };
}

module.exports = { securityMiddleware };
