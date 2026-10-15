const crypto = require('crypto');

function backoff(attempt) {
  return Math.min(30000, 2 ** attempt * 100 + Math.random() * 100);
}

function seal(key, data) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([iv, cipher.update(data), cipher.final()]);
}

function sealWeb(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
}

module.exports = { backoff, seal, sealWeb };
