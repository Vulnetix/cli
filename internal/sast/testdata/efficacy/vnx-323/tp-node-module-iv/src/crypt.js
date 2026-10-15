const crypto = require('crypto');

const key = crypto.scryptSync(process.env.PASSPHRASE, 'salt', 32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
~>  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

async function webEncrypt(k, data) {
~>  return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, data);
}

module.exports = { encrypt, webEncrypt };
