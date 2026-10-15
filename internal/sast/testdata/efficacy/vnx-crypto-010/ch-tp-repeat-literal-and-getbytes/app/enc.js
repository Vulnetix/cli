const crypto = require('crypto');
function enc(key, text) {
~>  const iv = Buffer.alloc(16, 0);
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  return c.update(text, 'utf8', 'hex') + c.final('hex');
}
