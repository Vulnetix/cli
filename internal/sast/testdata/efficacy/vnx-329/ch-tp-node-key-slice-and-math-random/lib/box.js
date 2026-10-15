const crypto = require('crypto');

function encrypt(key, text) {
~>  const cipher = crypto.createCipheriv('aes-256-cbc', key, key.slice(0, 16));
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function encrypt2(key, text) {
~>  const iv = Buffer.from(String(Math.random()).slice(2, 18));
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  return iv.toString('hex') + cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

module.exports = { encrypt, encrypt2 };
