const crypto = require('crypto');

const KEY = Buffer.from(process.env.COOKIE_KEY, 'base64');

function open(value) {
  const raw = Buffer.from(value, 'base64url');
  const iv = raw.subarray(0, 16);
~>  const decipher = crypto.createDecipheriv('aes-256-ctr', KEY, iv);
  return Buffer.concat([decipher.update(raw.subarray(16)), decipher.final()]).toString('utf8');
}

module.exports = { open };
