const crypto = require('crypto');

function readToken(req) {
  const buf = Buffer.from(req.cookies.token, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return JSON.parse(Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString());
}
