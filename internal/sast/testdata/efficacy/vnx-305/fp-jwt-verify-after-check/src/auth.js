const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    return res.sendStatus(401);
  }
  req.user = jwt.verify(token, process.env.JWT_SECRET);
  next();
}

function optional(req, res, next) {
  const token = req.headers.authorization;
  if (token) {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  }
  next();
}

module.exports = { requireAuth, optional };
