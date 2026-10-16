const jwt = require('jsonwebtoken');

module.exports = function jwtAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, { audience: 'api' });
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
};
