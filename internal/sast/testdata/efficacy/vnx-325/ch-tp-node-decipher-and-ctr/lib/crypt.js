const crypto = require('crypto');

function decrypt(key, payload) {
  const iv = payload.subarray(0, 16);
~>  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(payload.subarray(16)), decipher.final()]);
}

function encrypt(key, iv, data) {
  const cipher = crypto.createCipheriv(
~>    'aes-128-ctr',
    key,
    iv
  );
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

module.exports = { decrypt, encrypt };

function legacyEncrypt(key, iv, text) {
~>  const c = crypto.createCipheriv('aes256', key, iv);
  return c.update(text, 'utf8', 'hex') + c.final('hex');
}
