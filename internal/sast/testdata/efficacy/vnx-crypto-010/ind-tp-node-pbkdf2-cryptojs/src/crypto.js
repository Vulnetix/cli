const crypto = require('crypto');
const CryptoJS = require('crypto-js');

function deriveKey(password) {
~>  return crypto.pbkdf2Sync(password, 'static-app-salt', 310000, 32, 'sha256');
}

function encryptProfile(profile, secret) {
  const key = CryptoJS.enc.Utf8.parse(secret);
  return CryptoJS.AES.encrypt(JSON.stringify(profile), key, {
~>    iv: CryptoJS.enc.Utf8.parse('abcdefghijklmnop'),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  }).toString();
}

function encryptCookie(key, value) {
~>  const cipher = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16));
  return Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]).toString('base64');
}

module.exports = { deriveKey, encryptProfile, encryptCookie };
