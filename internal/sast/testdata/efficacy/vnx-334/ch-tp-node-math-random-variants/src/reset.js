const crypto = require('crypto');

function resetToken() {
~>  const resetToken = Math.floor(Math.random() * 1000000);
  return resetToken;
}

function sessionId() {
~>  const sessionId = Math.floor(100000 + Math.random() * 900000);
  return sessionId;
}

function apiSecret() {
~>  const apiSecret = crypto.randomInt(0, 999999);
  return apiSecret;
}

module.exports = { resetToken, sessionId, apiSecret };
