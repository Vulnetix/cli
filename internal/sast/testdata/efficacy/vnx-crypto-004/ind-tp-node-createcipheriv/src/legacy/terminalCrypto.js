const crypto = require('crypto');

function encryptPinBlock(key, iv, block) {
~>  const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function decryptArchive(key, iv, data) {
~>  const decipher = crypto.createDecipheriv("bf-cbc", key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

module.exports = { encryptPinBlock, decryptArchive };
