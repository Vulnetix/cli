const crypto = require('crypto');
const forge = require('node-forge');
const NodeRSA = require('node-rsa');

function nodePair() {
~>  return crypto.generateKeyPairSync('rsa', { modulusLength: 1024, publicKeyEncoding: { type: 'spki', format: 'pem' } });
}

function forgePair() {
~>  return forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
}

function nodeRsaPair() {
~>  return new NodeRSA({ b: 512 });
}

async function webPair() {
~>  return crypto.webcrypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
}

module.exports = { nodePair, forgePair, nodeRsaPair, webPair };
