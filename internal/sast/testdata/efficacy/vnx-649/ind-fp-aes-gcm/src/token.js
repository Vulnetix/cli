const crypto = require('crypto');

const KEY = Buffer.from(process.env.TOKEN_KEY, 'hex');

function openToken(req) {
  const buf = Buffer.from(req.cookies.token, 'base64url');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]);
  return JSON.parse(plain.toString('utf8'));
}

module.exports = { openToken };
