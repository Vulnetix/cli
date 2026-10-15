const crypto = require('crypto');

function adminOnly(req, res, next) {
  const apiKey = req.get('X-Api-Key');
  if (apiKey && crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(process.env.ADMIN_KEY))) {
    return next();
  }
  res.sendStatus(403);
}

function logRequest(req, res, next) {
  const requestId = req.headers['x-request-id'];
  if (requestId) {
    return next();
  }
  next();
}

module.exports = { adminOnly, logRequest };
