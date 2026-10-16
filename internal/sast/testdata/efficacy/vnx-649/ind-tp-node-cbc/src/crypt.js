const crypto = require('crypto');
const KEY = Buffer.from(process.env.APP_KEY, 'hex');

function readToken(req) {
  const buf = Buffer.from(req.cookies.tok, 'hex');
~>  const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, buf.subarray(0, 16));
  return Buffer.concat([decipher.update(buf.subarray(16)), decipher.final()]).toString();
}
