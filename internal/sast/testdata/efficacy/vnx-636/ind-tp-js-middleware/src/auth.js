const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization, process.env.SECRET);
    next();
  } catch (err) {
~>    next();
  }
}
module.exports = requireAuth;
