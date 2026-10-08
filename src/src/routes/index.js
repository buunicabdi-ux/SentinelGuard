const express = require('express');
const healthRouter = require('./health');
const { createInspectRouter } = require('./inspect');

function createRoutes(options) {
  const router = express.Router();
  router.use(healthRouter);
  router.use('/api/v1', createInspectRouter(options));
  return router;
}

module.exports = { createRoutes };
