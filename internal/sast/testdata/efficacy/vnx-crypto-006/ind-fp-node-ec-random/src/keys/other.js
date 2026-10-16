const crypto = require('crypto');

function ecPair() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

function strongPair() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
}

function buffer() {
  return crypto.randomBytes(1024);
}

module.exports = { ecPair, strongPair, buffer };
