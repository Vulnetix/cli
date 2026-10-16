const crypto = require('crypto');

function seal(encKey, macKey, plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  return Buffer.concat([iv, ct, tag]);
}

module.exports = { seal };
