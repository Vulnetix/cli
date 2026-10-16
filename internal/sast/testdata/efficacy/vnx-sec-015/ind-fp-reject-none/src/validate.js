const jwt = require('jsonwebtoken');

function verify(token, key) {
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url'));
  if (header.alg === 'none') {
    throw new Error('unsigned tokens are not accepted');
  }
  return jwt.verify(token, key, { algorithms: ['ES256'] });
}

module.exports = { verify };
