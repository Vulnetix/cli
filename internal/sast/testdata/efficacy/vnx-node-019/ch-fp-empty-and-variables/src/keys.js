const jwt = require('jsonwebtoken');
const fs = require('fs');

const privateKey = fs.readFileSync('/run/secrets/jwt.pem');
const hashAlgorithm = 'sha256';
const label = "jwt.sign(payload, 'secret') is a bad idea";

function issue(claims) {
  // jwt.sign(claims, 'hardcoded')
  return jwt.sign(claims, privateKey, { algorithm: 'RS256' });
}

module.exports = { issue, hashAlgorithm, label };
