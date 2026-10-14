const crypto = require('crypto');

module.exports = () => crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
