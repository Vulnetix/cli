const crypto = require('crypto');

function seal(key, text) {
~>  const iv = Buffer.from(String(Date.now()).padStart(16, '0')).subarray(0, 16);
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  return iv.toString('hex') + c.update(text, 'utf8', 'hex') + c.final('hex');
}

module.exports = { seal };
