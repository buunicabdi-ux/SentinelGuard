require('dotenv').config();

const { loadConfig } = require('./config');
const { createLogger } = require('./logger');
const { createApp } = require('./app');

const config = loadConfig(process.env);
const logger = createLogger(config.logLevel);
const app = createApp({ config, logger });
const server = app.listen(config.port, () => {
  logger.info('server_started', {
    port: config.port,
    environment: config.nodeEnv
  });
});

function shutdown(signal) {
  server.close((error) => {
    if (error) {
      logger.error('server_shutdown_failed', {
        signal,
        error: error.message
      });
      process.exitCode = 1;
      return;
    }

    logger.info('server_stopped', { signal });
  });
}

process.once('SIGINT', () => shutdown('SIGINT'));
process.once('SIGTERM', () => shutdown('SIGTERM'));
