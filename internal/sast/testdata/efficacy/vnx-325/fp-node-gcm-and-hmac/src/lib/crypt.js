const crypto = require('crypto');

function seal(key, text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(text), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

function etm(encKey, macKey, iv, text) {
  const c = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  const ct = Buffer.concat([c.update(text), c.final()]);
  const tag = crypto.createHmac('sha256', macKey).update(ct).digest();
  return Buffer.concat([iv, ct, tag]);
}

module.exports = { seal, etm };
