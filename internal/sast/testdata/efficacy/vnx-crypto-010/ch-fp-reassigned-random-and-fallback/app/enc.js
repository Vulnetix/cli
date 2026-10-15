const crypto = require('crypto');
function enc(key, text, opts) {
  const iv = opts.iv || crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const salt = crypto.randomBytes(16);
  const k = crypto.scryptSync(text, salt, 32);
  return [c, k];
}
