const crypto = require('crypto');
const iv = crypto.randomBytes(16);

function encrypt(key, text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return iv.toString('hex') + cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
module.exports = { encrypt, iv };
