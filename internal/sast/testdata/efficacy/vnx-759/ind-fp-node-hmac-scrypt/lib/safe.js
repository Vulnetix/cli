const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 64);
  return salt.toString('hex') + ':' + key.toString('hex');
}

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function fingerprint(buf) {
  return crypto.createHash('sha1').update(buf).digest('hex');
}

module.exports = { hashPassword, sign, fingerprint };
