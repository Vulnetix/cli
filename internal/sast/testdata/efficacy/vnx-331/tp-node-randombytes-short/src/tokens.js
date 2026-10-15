const crypto = require('crypto');

function resetToken() {
~>  const token = crypto.randomBytes(4).toString('hex');
  return token;
}

module.exports = {
~>  apiKey: () => crypto.randomBytes(8).toString('base64'),
};

function sessionId() {
~>  const sessionId = crypto.randomBytes( 6 ).toString('hex');
  return sessionId;
}
