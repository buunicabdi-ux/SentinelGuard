const express = require('express');
const path = require('node:path');
const { loadConfig } = require('./config');
const { createInspectionService } = require('./services/inspectionService');
const { createLogger } = require('./logger');
const { requestId } = require('./middleware/requestId');
const { securityMiddleware } = require('./middleware/security');
const { createErrorHandler, notFound } = require('./middleware/errorHandler');
const { createRoutes } = require('./routes');
const { AppError } = require('./errors');

function createApp({ config = loadConfig(process.env), analyzer, onAiFailure, logger } = {}) {
  const app = express();
  const appLogger = logger || createLogger(config.logLevel);
  const inspectionService = createInspectionService({ analyzer, onAiFailure, logger: appLogger });
  const { helmetMiddleware, corsMiddleware, limiter } = securityMiddleware(config);
  const inspectionPaths = new Set(['/api/v1/inspect', '/api/v1/inspect/payload']);
  const loggedRoutes = new Set([
    '/',
    '/app.js',
    '/styles.css',
    '/health',
    ...inspectionPaths
  ]);

  app.disable('x-powered-by');
  app.use(requestId);
  app.use((req, res, next) => {
    const startedAt = process.hrtime.bigint();
    const routePath = req.path;
    res.on('finish', () => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
      appLogger.info('http_request', {
        requestId: req.requestId,
        method: ['GET', 'POST', 'HEAD', 'OPTIONS'].includes(req.method) ? req.method : 'OTHER',
        route: loggedRoutes.has(routePath) ? routePath : 'other',
        status: res.statusCode,
        durationMs: Math.round(durationMs * 100) / 100,
        ...(res.locals.inspection || {})
      });
    });
    next();
  });
  app.use(helmetMiddleware);
  app.use(corsMiddleware);
  app.use(express.static(path.join(__dirname, '..', '..', 'public'), {
    index: 'index.html',
    fallthrough: true,
    setHeaders(res) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }));
  app.use(limiter);
  app.use((req, res, next) => {
    if (req.method === 'POST' && inspectionPaths.has(req.path) &&
        !req.is(['application/json', 'application/*+json'])) {
      next(new AppError('Content-Type must be application/json', 415, 'UNSUPPORTED_MEDIA_TYPE'));
      return;
    }
    next();
  });
  app.use(express.json({ limit: config.jsonBodyLimit, strict: true }));
  app.use(createRoutes({
    inspectionService,
    maxInputChars: config.maxInputChars
  }));
  app.use(notFound);
  app.use(createErrorHandler(appLogger));

  return app;
}

module.exports = { createApp };
