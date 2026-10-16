const forge = require('node-forge');
function enc(key, iv, data) {
  const cipher = forge.cipher.createCipher('AES-CBC', key);
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(data));
  cipher.finish();
  return cipher.output;
}
module.exports = enc;
