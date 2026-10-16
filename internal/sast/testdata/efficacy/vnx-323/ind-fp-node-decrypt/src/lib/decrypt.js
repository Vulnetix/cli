const crypto = require('crypto');

const key = Buffer.from(process.env.DATA_KEY, 'hex');
const fallbackIv = crypto.randomBytes(16);

function decrypt(hex, ivHex) {
  const iv = ivHex ? Buffer.from(ivHex, 'hex') : fallbackIv;
  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  return Buffer.concat([decipher.update(Buffer.from(hex, 'hex')), decipher.final()]).toString();
}

module.exports = { decrypt };
