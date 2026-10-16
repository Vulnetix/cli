const crypto = require('crypto');

function makeResetToken() {
~>  const resetToken = crypto.randomInt(100000, 999999);
  return resetToken;
}

function makeSessionId() {
~>  const sessionId = Math.floor(Math.random() * 1000000);
  return sessionId;
}

module.exports = { makeResetToken, makeSessionId };
