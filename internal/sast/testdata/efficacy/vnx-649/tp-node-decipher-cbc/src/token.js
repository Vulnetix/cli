const crypto = require('crypto');

function readToken(req) {
  const buf = Buffer.from(req.cookies.token, 'hex');
~>  const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, buf.subarray(0, 16));
  const out = Buffer.concat([decipher.update(buf.subarray(16)), decipher.final()]);
  return JSON.parse(out.toString());
}
