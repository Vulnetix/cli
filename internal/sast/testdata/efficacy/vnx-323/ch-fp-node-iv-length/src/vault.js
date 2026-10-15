const crypto = require('crypto');

const IV_LENGTH = 16;
const ALGORITHM = 'aes-256-cbc';

function encrypt(key, text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  return Buffer.concat([iv, cipher.update(text), cipher.final()]);
}

module.exports = { encrypt };
