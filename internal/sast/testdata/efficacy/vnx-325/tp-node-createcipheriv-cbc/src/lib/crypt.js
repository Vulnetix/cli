const crypto = require('crypto');

function encrypt(key, text) {
  const iv = crypto.randomBytes(16);
~>  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([iv, cipher.update(text), cipher.final()]);
}

function decrypt(key, buf) {
~>  const decipher = crypto.createDecipheriv("aes-128-ctr", key, buf.subarray(0, 16));
  return Buffer.concat([decipher.update(buf.subarray(16)), decipher.final()]);
}

module.exports = { encrypt, decrypt };
