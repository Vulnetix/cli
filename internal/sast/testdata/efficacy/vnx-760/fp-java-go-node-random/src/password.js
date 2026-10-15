const crypto = require('crypto');

function hash(password) {
  const salt = crypto.randomBytes(16);
  return crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
}

function hash2(password, user) {
  return crypto.scryptSync(password, user.salt, 64);
}
