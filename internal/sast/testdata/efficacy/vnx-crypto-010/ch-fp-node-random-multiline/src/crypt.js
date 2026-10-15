const crypto = require('crypto');

function encrypt(key, text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    key,
    iv
  );
  return Buffer.concat([iv, cipher.update(text), cipher.final(), cipher.getAuthTag()]);
}

function derive(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
}

module.exports = { encrypt, derive };
