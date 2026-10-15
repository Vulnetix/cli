const crypto = require('crypto');

function encrypt(key, text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([iv, cipher.update(text), cipher.final()]);
}

function decrypt(key, buf) {
  const iv = buf.slice(0, 16);
  return crypto.createDecipheriv('aes-256-cbc', key, iv).update(buf.slice(16));
}

const keyPrefix = apiKey.slice(0, 16);
