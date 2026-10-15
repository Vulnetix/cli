const crypto = require('crypto');
const { randomBytes } = require('crypto');

function createResetToken() {
~>  const resetToken = crypto.randomBytes(8).toString('hex');
  return resetToken;
}

function createApiKey() {
~>  const apiKey = randomBytes(4).toString('base64');
  return apiKey;
}

module.exports = { createResetToken, createApiKey };
