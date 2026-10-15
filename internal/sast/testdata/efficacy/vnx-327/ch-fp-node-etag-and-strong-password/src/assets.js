const crypto = require('crypto');
const bcrypt = require('bcrypt');

function etagFor(buffer) {
  return '"' + crypto.createHash('md5').update(buffer).digest('base64') + '"';
}

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

function sign(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

module.exports = { etagFor, hashPassword, sign };
