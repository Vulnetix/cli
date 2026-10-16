const crypto = require('crypto');

function seal(key, text) {
~>  const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
  return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]).toString('base64');
}

function open(key, b64) {
~>  const decipher = crypto.createDecipheriv("aes-128-ecb", key, Buffer.alloc(0));
  return Buffer.concat([decipher.update(Buffer.from(b64, 'base64')), decipher.final()]).toString('utf8');
}

module.exports = { seal, open };
