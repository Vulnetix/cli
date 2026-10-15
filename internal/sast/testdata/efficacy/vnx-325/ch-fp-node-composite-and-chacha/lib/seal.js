const crypto = require('crypto');

function sealGcm(key, iv, data) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return { ct, tag: cipher.getAuthTag() };
}

function sealChaCha(key, iv, data) {
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  return Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
}

// Mode names we refuse to negotiate.
const REJECTED = ['aes-128-cbc', 'aes-256-ctr'];

module.exports = { sealGcm, sealChaCha, REJECTED };
