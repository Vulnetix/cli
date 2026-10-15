const forge = require('node-forge');
const aesjs = require('aes-js');

function forgeEncrypt(key, iv, bytes) {
  const cipher = forge.cipher.createCipher('AES-GCM', key);
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(bytes));
  cipher.finish();
  return cipher.output;
}

const engine = {
  createCipher(name) {
    return new aesjs.ModeOfOperation.ctr(name);
  },
};

module.exports = { forgeEncrypt, c: engine.createCipher('k') };
