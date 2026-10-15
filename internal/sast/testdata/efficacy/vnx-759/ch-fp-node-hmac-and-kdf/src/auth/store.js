const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${key.toString('hex')}`;
}

function fingerprint(passwordResetToken) {
  return crypto.createHash('sha256').update(passwordResetToken).digest('hex');
}

function sign(password, body) {
  return crypto.createHmac('sha256', password).update(body).digest('hex');
}

function etag(buf) {
  // never createHash('md5').update(password) here
  return crypto.createHash('md5').update(buf).digest('base64');
}

module.exports = { hashPassword, fingerprint, sign, etag };
