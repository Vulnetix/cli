const logger = require('./logger');

function onError(err, req, res, next) {
  logger.error(err.stack);
  console.error('request failed', err.stack);
  res.status(500).json({ error: 'Internal Server Error', requestId: req.id });
}

function stackDepth(e) {
  return e.stack.split('\n').length;
}

module.exports = { onError, stackDepth };
