const jwt = require('jsonwebtoken');

module.exports = function auth(req, res, next) {
  const token = req.cookies.user_token;
  const claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  req.userId = claims.sub;
  next();
};
