const fs = require('fs');
const jwt = require('jsonwebtoken');

const privateKey = fs.readFileSync('./keys/private.pem');

function sign(payload) {
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '1h' });
}

function signInline(payload) {
  return jwt.sign(payload, fs.readFileSync('/etc/app/jwt.key'), { algorithm: 'RS256', expiresIn: '1h' });
}

module.exports = { sign, signInline };
