const crypto = require('crypto');

function resetToken() {
~>  const resetToken = crypto.randomInt(100000, 999999);
  return String(resetToken);
}

function sessionId() {
~>  const sessionId = Math.floor(Math.random() * 1000000);
  return sessionId;
}
