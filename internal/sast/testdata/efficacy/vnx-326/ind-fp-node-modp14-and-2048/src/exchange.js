const crypto = require('crypto');

// modp2 is a 1024-bit group and is not used here.
function exchange() {
  const group = crypto.getDiffieHellman('modp14');
  group.generateKeys();
  return group;
}

function signer() {
  return crypto.generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 });
}

module.exports = { exchange, signer };
