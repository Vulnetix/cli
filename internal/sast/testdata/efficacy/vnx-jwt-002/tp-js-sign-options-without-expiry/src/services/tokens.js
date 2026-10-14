const jwt = require('jsonwebtoken');

function issue(user, privateKey) {
~>  return jwt.sign(
    { sub: user.id, scope: user.scopes.join(' ') },
    privateKey,
    { algorithm: 'RS256', issuer: 'shop' }
  );
}

module.exports = { issue };
