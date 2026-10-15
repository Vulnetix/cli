const { v1: uuidv1 } = require('uuid');
const { randomUUID } = require('crypto');

module.exports = function trace(req, res, next) {
  const traceId = uuidv1();
  req.traceId = traceId;
  res.locals.token = randomUUID();
  next();
};
