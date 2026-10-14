const crypto = require('crypto');
const config = require('../config');

function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return iv.toString('hex') + ':' + Buffer.concat([cipher.update(text), cipher.final()]).toString('hex');
}

function decrypt(payload, key) {
  const parts = payload.split(':');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(parts[0], 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(parts[1], 'hex')), decipher.final()]).toString();
}

function filled(text, key) {
  const iv = Buffer.alloc(16);
  crypto.randomFillSync(iv);
  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  return Buffer.concat([iv, cipher.update(text), cipher.final()]);
}

function fromConfig(text) {
  const cipher = crypto.createCipheriv(config.cryptoAlgo, config.cryptoKey, config.iv);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  return crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
}

async function webEncrypt(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { iv, ct };
}

async function webEncrypt2(key, data) {
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv: crypto.getRandomValues(new Uint8Array(12)) }, key, data);
}

const options = { iv: 'none', retries: 3 };

module.exports = { encrypt, decrypt, filled, fromConfig, hashPassword, webEncrypt, webEncrypt2, options };
