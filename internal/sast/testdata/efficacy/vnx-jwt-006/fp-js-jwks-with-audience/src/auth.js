const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({ jwksUri: 'https://tenant.example.com/.well-known/jwks.json' });
const verifyOptions = { algorithms: ['RS256'], audience: 'orders-api' };

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => callback(err, key && key.getPublicKey()));
}

function verify(token, cb) {
  jwt.verify(token, getKey, verifyOptions, cb);
}

module.exports = { verify };
