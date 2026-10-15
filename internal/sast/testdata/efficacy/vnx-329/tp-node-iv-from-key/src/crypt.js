const crypto = require('crypto');

function encrypt(key, text) {
~>  const cipher = crypto.createCipheriv('aes-256-cbc', key, key.slice(0, 16));
  return Buffer.concat([cipher.update(text), cipher.final()]);
}

function encrypt2(secretKey, text) {
~>  const iv = Buffer.from(secretKey).subarray(0, 16);
  const cipher = crypto.createCipheriv('aes-128-cbc', secretKey, iv);
  return Buffer.concat([cipher.update(text), cipher.final()]);
}

function encrypt3(key, text) {
~>  const iv = Buffer.from(Array.from({ length: 16 }, () => Math.floor(Math.random() * 256)));
  return crypto.createCipheriv('aes-256-cbc', key, iv).update(text);
}
