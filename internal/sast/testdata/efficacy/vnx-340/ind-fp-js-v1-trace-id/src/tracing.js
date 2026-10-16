const { v1: uuidv1 } = require('uuid');
const crypto = require('crypto');

function middleware(req, res, next) {
  req.traceId = uuidv1();
  res.setHeader('X-Request-Id', req.traceId);
  req.csrfToken = crypto.randomUUID();
  next();
}

module.exports = middleware;
