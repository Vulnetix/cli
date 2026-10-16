const jwt = require('jsonwebtoken');

function guard(token, key) {
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
  if (header.alg.toLowerCase() === 'none') {
    throw new Error('unsigned tokens are not accepted');
  }
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}
module.exports = { guard };
