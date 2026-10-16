const crypto = require('crypto');

async function encryptGcm(key, data) {
  const iv = new Uint8Array(12);
  crypto.webcrypto.getRandomValues(iv);
  const ct = await crypto.webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { iv, ct };
}

function encryptCbc(key, text) {
  const iv = Buffer.alloc(16);
  crypto.randomFillSync(iv);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return iv.toString('hex') + ':' + cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function decryptCbc(key, payload) {
  const parts = payload.split(':');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(parts[0], 'hex'));
  return decipher.update(parts[1], 'hex', 'utf8') + decipher.final('utf8');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  return { salt, hash: crypto.scryptSync(password, salt, 64) };
}

function withConfig(config, data) {
  return crypto.createCipheriv(config.algorithm, config.key, config.iv).update(data);
}

module.exports = { encryptGcm, encryptCbc, decryptCbc, hashPassword, withConfig };
