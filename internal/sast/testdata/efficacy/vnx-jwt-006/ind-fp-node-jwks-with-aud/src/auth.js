const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({ jwksUri: 'https://idp.example.org/.well-known/jwks.json' });
function getKey(header, cb) {
  client.getSigningKey(header.kid, (err, key) => cb(err, key && key.getPublicKey()));
}
function check(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, { algorithms: ['RS256'], audience: 'orders-api', issuer: 'https://idp.example.org/' }, (e, d) => e ? reject(e) : resolve(d));
  });
}
module.exports = { check };
