const jwt = require('jsonwebtoken');
const jwks = require('./jwks');

async function authenticate(req) {
  const token = req.headers.authorization.replace('Bearer ', '');
  const decoded = jwt.decode(token, { complete: true });
  const key = await jwks.getSigningKey(decoded.header.kid);
  return jwt.verify(token, key.getPublicKey(), { algorithms: ['RS256'] });
}

module.exports = { authenticate };
