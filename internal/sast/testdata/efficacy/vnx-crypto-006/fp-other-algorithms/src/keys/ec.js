const crypto = require('crypto');

const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const buf = Buffer.alloc(1024);
const dh = crypto.generateKeyPairSync('dsa', {
  modulusLength: 1024,
});

module.exports = { pair, buf, dh };
