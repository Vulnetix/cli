const crypto = require('crypto');

// Do not use key.slice(0, 16) as the IV.
function encrypt(key, text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([iv, cipher.update(text, 'utf8'), cipher.final()]);
}

module.exports = { encrypt };
