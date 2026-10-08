function notFound(req, res) {
  res.status(404).json({
    success: false,
    error: { code: 'NOT_FOUND', message: 'Route not found' },
    requestId: req.requestId
  });
}

function createErrorHandler(logger) {
  return function errorHandler(error, req, res, next) {
    if (res.headersSent) {
      next(error);
      return;
    }

    const unsupportedParserType = error.type === 'encoding.unsupported' ||
      error.type === 'charset.unsupported';
    const parserStatus = error.type === 'entity.too.large' ? 413
      : unsupportedParserType ? 415
        : error.type === 'entity.parse.failed' || error.type === 'request.size.invalid' ? 400
        : Number.isInteger(error.status) ? error.status : null;
    const isBodyParserError = error.type === 'entity.too.large' ||
      error.type === 'entity.parse.failed' || error.type === 'request.size.invalid' ||
      unsupportedParserType;
    const knownStatus = !isBodyParserError && Number.isInteger(error.statusCode) &&
      error.statusCode >= 400 && error.statusCode <= 599;
    const statusCode = knownStatus ? error.statusCode : isBodyParserError ? parserStatus : 500;
    const code = knownStatus ? error.code
      : parserStatus === 413 ? 'REQUEST_TOO_LARGE'
        : parserStatus === 415 ? 'UNSUPPORTED_MEDIA_TYPE'
        : parserStatus === 400 ? 'MALFORMED_JSON'
          : 'INTERNAL_ERROR';
    const message = knownStatus ? error.message
      : parserStatus === 413 ? 'Request body exceeds the configured size limit'
        : parserStatus === 415 ? 'Request content type or encoding is not supported'
        : parserStatus === 400 ? 'Request body contains malformed JSON'
          : 'An unexpected error occurred';

    if ((!knownStatus && !isBodyParserError) || statusCode >= 500) {
      logger.error('request_failed', { requestId: req.requestId, code });
    }

    res.status(statusCode).json({
      success: false,
      error: { code, message },
      requestId: req.requestId
    });
  };
}

module.exports = { createErrorHandler, notFound };
