const crypto = require('crypto');

function newNonce() {
  const nonce = crypto.randomBytes(12);
  return nonce;
}

function requestId() {
  const requestId = crypto.randomBytes(4).toString('hex');
  return requestId;
}

function sessionSecret() {
  const sessionSecret = crypto.randomBytes(32).toString('hex');
  return sessionSecret;
}

module.exports = { newNonce, requestId, sessionSecret };
