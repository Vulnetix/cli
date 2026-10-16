const crypto = require('crypto');

function encrypt(text, password) {
~>  const cipher = crypto.createCipher('aes-256-cbc', password);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
module.exports = encrypt;
