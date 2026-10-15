const crypto = require('crypto');

function dsaPair() {
  return crypto.generateKeyPairSync('dsa', {
~>    modulusLength: 1024,
    divisorLength: 160,
  });
}

function dhGroup() {
~>  return crypto.createDiffieHellman(512);
}

function ecdh() {
~>  return crypto.createECDH('prime192v1');
}

module.exports = { dsaPair, dhGroup, ecdh };
