const jwt = require('jsonwebtoken');
const fs = require('fs');

const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH);

function requireUser(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer\s+/i, '');
  if (!token) {
    return res.status(401).json({ error: 'missing token' });
  }
  try {
    req.user = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      audience: 'api.acme.io',
~>      ignoreExpiration: true,
    });
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

module.exports = { requireUser };
