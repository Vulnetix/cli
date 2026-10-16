const crypto = require('crypto');

function derive(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
  return { salt, key };
}

module.exports = { derive };
