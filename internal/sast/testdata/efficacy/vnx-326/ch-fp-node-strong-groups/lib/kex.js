const crypto = require('crypto');

const dsa = crypto.generateKeyPairSync('dsa', { modulusLength: 3072, divisorLength: 256 });
const dh = crypto.createDiffieHellman(2048);
const group = crypto.getDiffieHellman('modp14');
const ecdh = crypto.createECDH('prime256v1');
const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
const buf = Buffer.alloc(512);

module.exports = { dsa, dh, group, ecdh, rsa, buf };
