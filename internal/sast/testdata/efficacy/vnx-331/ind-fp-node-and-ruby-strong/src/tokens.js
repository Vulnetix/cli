const crypto = require('crypto');

// crypto.randomBytes(4) would be far too short for a token.
function sessionToken() {
  const token = crypto.randomBytes(32).toString('hex');
  return token;
}

module.exports = { sessionToken };
