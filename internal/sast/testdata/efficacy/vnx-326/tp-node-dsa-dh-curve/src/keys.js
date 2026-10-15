const crypto = require('crypto');

function dsaKeys() {
~>  return crypto.generateKeyPairSync('dsa', { modulusLength: 1024, divisorLength: 160 });
}

function dhGroup() {
~>  const dh = crypto.createDiffieHellman(512);
  return dh.generateKeys();
}

function legacyGroup() {
~>  return crypto.getDiffieHellman('modp2');
}

function ecKeys() {
~>  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime192v1' });
}

function ecdh() {
~>  return crypto.createECDH('secp160r1');
}
