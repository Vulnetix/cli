const crypto = require('crypto');

const key = Buffer.from(process.env.DATA_KEY, 'hex');
const iv = crypto.randomBytes(16);

function encrypt(text) {
~>  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]).toString('hex');
}

module.exports = { encrypt };
