const jwt = require('jsonwebtoken');

function auth(req, res, next) {
  const token = req.headers.authorization.split(' ')[1];
~>  const claims = jwt.decode(token);
  if (claims && claims.role === 'admin') return next();
  res.status(403).end();
}
module.exports = auth;
