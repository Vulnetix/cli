const crypto = require('crypto');

const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const dh = crypto.getDiffieHellman('modp14');
const ecdh = crypto.createECDH('prime256v1');
const d2 = crypto.createDiffieHellman(2048);
const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
