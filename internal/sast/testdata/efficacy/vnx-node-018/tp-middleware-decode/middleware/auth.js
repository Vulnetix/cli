const jwt = require('jsonwebtoken');
const User = require('../models/user');

module.exports = async function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer\s+/i, '');
  if (!token) {
    return res.status(401).end();
  }
~>  const claims = jwt.decode(token);
  req.user = await User.findById(claims.sub);
  next();
};
