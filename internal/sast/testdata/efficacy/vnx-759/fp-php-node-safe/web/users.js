const crypto = require('crypto');

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function salted(password, salt) {
  return crypto.createHash('sha256').update(salt + password).digest('hex');
}

function etag(body) {
  return crypto.createHash('sha1').update(body).digest('base64');
}

function hmac(password, key) {
  return crypto.createHmac('sha256', key).update(password).digest('hex');
}
