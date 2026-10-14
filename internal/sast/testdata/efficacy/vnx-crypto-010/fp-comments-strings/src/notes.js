// const cipher = crypto.createCipheriv('aes-256-cbc', key, '0000000000000000');
/* crypto.pbkdf2Sync(password, 'salt', 1000, 32, 'sha256') is the bad example */
const crypto = require('crypto');

const docs = "crypto.createCipheriv('aes-256-cbc', key, '1234567890123456')";

function encrypt(text, key) {
  const iv = crypto.randomBytes(16); // never Buffer.alloc(16)
  return crypto.createCipheriv('aes-256-cbc', key, iv).update(text);
}

module.exports = { docs, encrypt };
