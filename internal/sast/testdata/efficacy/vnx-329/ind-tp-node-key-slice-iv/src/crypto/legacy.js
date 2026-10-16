const crypto = require('crypto');

function encrypt(key, text) {
~>  const cipher = crypto.createCipheriv('aes-256-cbc', key, key.slice(0, 16));
  return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]).toString('base64');
}

module.exports = { encrypt };
