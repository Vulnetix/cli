const crypto = require('crypto');

function digest(password) {
  return crypto.createHash('sha256').update(password).digest('base64');
}

function stored(passwordHash) {
  return Buffer.from(passwordHash).toString('base64');
}
module.exports = { digest, stored };
