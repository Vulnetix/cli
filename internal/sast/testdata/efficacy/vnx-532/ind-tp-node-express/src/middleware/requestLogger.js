const logger = require("../logger");

function requestLogger(req, res, next) {
~>  logger.info(`headers: ${JSON.stringify(req.headers)}`);
~>  console.log("body", req.body);
~>  logger.debug({ path: req.path, cookies: req.cookies }, "incoming request");
  next();
}

function authDebug(req, res, next) {
~>  console.log("auth:", req.headers.authorization);
  next();
}

module.exports = { requestLogger, authDebug };
