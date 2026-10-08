const { randomUUID } = require('node:crypto');

const SAFE_REQUEST_ID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;

function requestId(req, res, next) {
  const supplied = req.get('x-request-id');
  const id = supplied && SAFE_REQUEST_ID.test(supplied) ? supplied : randomUUID();
  req.requestId = id;
  res.setHeader('X-Request-Id', id);
  next();
}

module.exports = { requestId };
