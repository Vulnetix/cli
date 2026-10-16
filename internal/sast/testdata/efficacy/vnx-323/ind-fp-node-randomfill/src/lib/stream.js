const crypto = require('crypto');

const iv = Buffer.alloc(16);

function encryptChunk(key, chunk) {
  crypto.randomFillSync(iv);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([iv, cipher.update(chunk), cipher.final()]);
}

module.exports = { encryptChunk };
