const jwt = require('jsonwebtoken');

function requireUser(req, res, next) {
  const token = req.headers.authorization.split(' ')[1];
~>  const user = jwt.decode(token);
  if (!user) {
    return res.status(401).end();
  }
  req.user = user;
  next();
}

function isAdmin(req) {
~>  return jwt.decode(req.cookies.token).role === 'admin';
}

module.exports = { requireUser, isAdmin };
