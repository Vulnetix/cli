const logger = require("../logger");

const REDACTED = new Set(["authorization", "cookie", "x-api-key"]);

function requestLogger(req, res, next) {
  logger.info({ method: req.method, path: req.path, requestId: req.headers["x-request-id"] }, "request");
  logger.debug(`content-length ${req.headers["content-length"]}`);
  logger.debug("body keys", Object.keys(req.body || {}));
  if (req.headers.authorization) {
    logger.debug("authorization header present");
  }
  res.json({ echo: req.body });
  next();
}

module.exports = { requestLogger, REDACTED };
