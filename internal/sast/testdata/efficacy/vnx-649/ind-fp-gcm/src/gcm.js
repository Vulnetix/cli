const crypto = require('crypto');
function read(req, key) {
  const buf = Buffer.from(req.cookies.tok, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString();
}
