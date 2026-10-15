const crypto = require('crypto');

function requestOptions() {
  const delay = Math.random() * 1000;
  const maxTokens = Math.floor(Math.random() * 100) + 200;
  const token = crypto.randomBytes(32).toString('hex');
  return { delay, maxTokens, token };
}

module.exports = { requestOptions };
