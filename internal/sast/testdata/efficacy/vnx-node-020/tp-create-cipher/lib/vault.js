const crypto = require('crypto');

function encrypt(text, password) {
~>  const cipher = crypto.createCipher('aes-256-cbc', password);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function decrypt(hex, password) {
~>  const decipher = crypto.createDecipher('aes-256-cbc', password);
  return decipher.update(hex, 'hex', 'utf8') + decipher.final('utf8');
}

module.exports = { encrypt, decrypt };
