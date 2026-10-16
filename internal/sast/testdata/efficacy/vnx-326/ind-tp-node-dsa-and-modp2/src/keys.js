const crypto = require('crypto');

function legacySigningPair() {
~>  return crypto.generateKeyPairSync('dsa', { modulusLength: 1024 });
}

function legacyExchange() {
~>  const group = crypto.getDiffieHellman('modp2');
  group.generateKeys();
  return group;
}

module.exports = { legacySigningPair, legacyExchange };
