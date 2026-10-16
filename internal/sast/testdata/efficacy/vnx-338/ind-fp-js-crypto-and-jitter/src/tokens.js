const crypto = require('crypto');

function newResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

function retryDelay(attempt) {
  const jitter = Math.random() * 250;
  return Math.min(30000, 2 ** attempt * 100 + jitter);
}

const sessionId = crypto.randomUUID();

module.exports = { newResetToken, retryDelay, sessionId };
