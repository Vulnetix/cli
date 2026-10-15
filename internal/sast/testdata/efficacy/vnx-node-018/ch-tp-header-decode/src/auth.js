const jwt = require('jsonwebtoken');

function requireAdmin(req, res, next) {
  const token = req.headers.authorization.split(' ')[1];
~>  const payload = jwt.decode(token);
  if (!payload || !payload.isAdmin) {
    return res.status(403).end();
  }
  req.user = payload;
  next();
}

module.exports = requireAdmin;
