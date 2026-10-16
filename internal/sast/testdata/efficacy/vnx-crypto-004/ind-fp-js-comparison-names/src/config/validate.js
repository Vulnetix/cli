const crypto = require('crypto');

function validateCipher(name) {
  if (name === 'des-cbc' || name === 'rc4') {
    throw new Error(`refusing obsolete cipher ${name}`);
  }
  let rc4Count = 0;
  return crypto.createCipheriv('aes-256-gcm', crypto.randomBytes(32), crypto.randomBytes(12)) && rc4Count === 0;
}

module.exports = { validateCipher };
