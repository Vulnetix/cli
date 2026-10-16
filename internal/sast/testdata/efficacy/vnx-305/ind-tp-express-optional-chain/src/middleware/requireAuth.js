'use strict';

const logger = require('../lib/logger');

function requireAuth(req, res, next) {
  const bearer = req.headers.authorization?.split(' ')[1];
~>  if (bearer) return next();
  logger.warn({ path: req.path }, 'rejected request without bearer token');
  return res.status(401).json({ error: 'unauthorized' });
}

module.exports = { requireAuth };
