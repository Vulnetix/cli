const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.split(' ')[1];
  if (!token) return res.sendStatus(401);
~>  const user = jwt.decode(token);
  req.user = user;
  next();
}

module.exports = { authenticate };
