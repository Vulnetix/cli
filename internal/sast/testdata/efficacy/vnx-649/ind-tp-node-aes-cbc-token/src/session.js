const crypto = require('crypto');

const KEY = Buffer.from(process.env.SESSION_KEY, 'hex');

function readSession(req) {
  const buf = Buffer.from(req.cookies.sid, 'base64');
  const iv = buf.subarray(0, 16);
~>  const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, iv);
  const plain = Buffer.concat([decipher.update(buf.subarray(16)), decipher.final()]);
  return plain.toString('utf8');
}

module.exports = { readSession };
