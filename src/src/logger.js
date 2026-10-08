const LEVEL_PRIORITY = Object.freeze({
  fatal: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4
});

function createLogger(minimumLevel = 'info') {
  const minimumPriority = LEVEL_PRIORITY[minimumLevel];

  function write(level, event, fields = {}) {
    if (LEVEL_PRIORITY[level] > minimumPriority) return;
    const line = JSON.stringify({ level, event, ...fields });
    if (level === 'fatal' || level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
  }

  return {
    fatal: (event, fields) => write('fatal', event, fields),
    error: (event, fields) => write('error', event, fields),
    warn: (event, fields) => write('warn', event, fields),
    info: (event, fields) => write('info', event, fields),
    debug: (event, fields) => write('debug', event, fields)
  };
}

module.exports = { createLogger };
