const crypto = require('crypto');

// crypto.createCipher('aes-256-cbc', password) was removed in Node 22.
/* const d = crypto.createDecipher('aes192', key) */
const NOTE = 'replace crypto.createCipher() with crypto.createCipheriv()';

function upgrade(key, iv) {
  return crypto.createCipheriv('aes-256-cbc', key, iv);
}

module.exports = { upgrade, NOTE };
