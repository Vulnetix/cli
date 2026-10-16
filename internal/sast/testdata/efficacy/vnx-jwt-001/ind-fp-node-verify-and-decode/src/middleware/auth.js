const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  try {
    jwt.verify(token, process.env.JWT_KEY, { algorithms: ['HS256'] });
  } catch (e) {
    return res.sendStatus(401);
  }
  const payload = jwt.decode(token);
  req.user = payload;
  next();
}
module.exports = { authenticate };
