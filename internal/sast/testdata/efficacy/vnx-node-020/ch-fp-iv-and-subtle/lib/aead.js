const crypto = require('crypto');

function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const out = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, out, tag: cipher.getAuthTag() };
}

async function webEncrypt(key, data) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  return globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
}

function decrypt(key, iv, data, tag) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]);
}

module.exports = { encrypt, decrypt, webEncrypt };
