const crypto = require('crypto');
function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const out = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return { iv, out, tag: cipher.getAuthTag() };
}
function decrypt(o, key) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, o.iv);
  d.setAuthTag(o.tag);
  return Buffer.concat([d.update(o.out), d.final()]);
}
module.exports = { encrypt, decrypt };
