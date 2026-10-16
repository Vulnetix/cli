const jwt = require('jsonwebtoken');
~>const privateKey = '-----BEGIN PRIVATE KEY-----\n@@sample:[A-Za-z0-9+/]{64}@@\n-----END PRIVATE KEY-----';
module.exports = (p) => jwt.sign(p, privateKey, { algorithm: 'RS256' });
