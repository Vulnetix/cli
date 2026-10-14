const crypto = require('crypto');
const CryptoJS = require('crypto-js');

function encrypt(text, key) {
~>  const cipher = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16, 0));
  return Buffer.concat([cipher.update(text), cipher.final()]);
}

function decrypt(buf, key) {
~>  const decipher = crypto.createDecipheriv("aes-128-cbc", key, "1234567890123456");
  return Buffer.concat([decipher.update(buf), decipher.final()]).toString();
}

function encryptWrapped(text, key) {
~>  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(key, 'hex'),
    Buffer.from('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', 'hex'),
  );
  return cipher.update(text, 'utf8', 'base64') + cipher.final('base64');
}

function browserCompat(msg, key) {
~>  return CryptoJS.AES.encrypt(msg, key, { iv: CryptoJS.enc.Utf8.parse("1234567812345678"), mode: CryptoJS.mode.CBC }).toString();
}

module.exports = { encrypt, decrypt, encryptWrapped, browserCompat };
