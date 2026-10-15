const crypto = require("crypto");
const forge = require("node-forge");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
~>  modulusLength: 1024,
  publicExponent: 0x10001,
});

~>const kp = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });

module.exports = { publicKey, privateKey, kp };
