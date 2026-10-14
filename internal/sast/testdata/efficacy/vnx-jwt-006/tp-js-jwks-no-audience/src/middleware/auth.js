const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({ jwksUri: 'https://tenant.example.com/.well-known/jwks.json' });

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => callback(err, key && key.getPublicKey()));
}

module.exports = function requireUser(req, res, next) {
  const token = req.headers.authorization.split(' ')[1];
~>  jwt.verify(token, getKey, { algorithms: ['RS256'], issuer: 'https://tenant.example.com/' }, (err, user) => {
    if (err) return res.status(401).end();
    req.user = user;
    next();
  });
};
