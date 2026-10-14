const jwt = require('jsonwebtoken');
const keys = require('./keys');

// The header is read only to choose the key; the token is then verified.
function verifyToken(token) {
  const { header } = jwt.decode(token, { complete: true });
  const key = keys[header.kid];
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}

module.exports = { verifyToken };
