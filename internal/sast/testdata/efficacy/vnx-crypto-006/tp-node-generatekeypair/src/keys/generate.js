const crypto = require('crypto');
const forge = require('node-forge');
const NodeRSA = require('node-rsa');

function weakPair() {
  return crypto.generateKeyPairSync('rsa', {
~>    modulusLength: 1024,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function oneLine(cb) {
~>  crypto.generateKeyPair('rsa', { modulusLength: 512 }, cb);
}

function withForge() {
~>  return forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
}

function withNodeRsa() {
~>  return new NodeRSA({ b: 512 });
}

module.exports = { weakPair, oneLine, withForge, withNodeRsa };
