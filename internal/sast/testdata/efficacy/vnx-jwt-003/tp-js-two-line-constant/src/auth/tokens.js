const jwt = require('jsonwebtoken');

~>const signingKey = 'kZ8#dev-signing-key';

function issue(user) {
  return jwt.sign({ sub: user.id }, signingKey, { expiresIn: '15m' });
}

module.exports = { issue };
