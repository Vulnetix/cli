const jwt = require('jsonwebtoken');

const verifyOptions = {
  algorithms: ['RS256'],
  issuer: 'https://id.acme.example',
~>  ignoreExpiration: true,
};

module.exports = function requireUser(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer /, '');
  try {
    req.user = jwt.verify(token, process.env.JWT_PUBLIC_KEY, verifyOptions);
    next();
  } catch (err) {
    res.status(401).end();
  }
};
