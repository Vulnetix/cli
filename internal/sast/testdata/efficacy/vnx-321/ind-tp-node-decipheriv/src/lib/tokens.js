const crypto = require('crypto');

function decrypt(payload) {
  const [ivHex, dataHex] = payload.split(':');
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
~>    'f3a9c2e17b8d4065a3f9c2e17b8d4065',
    Buffer.from(ivHex, 'hex'),
  );
  return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString();
}

module.exports = { decrypt };
