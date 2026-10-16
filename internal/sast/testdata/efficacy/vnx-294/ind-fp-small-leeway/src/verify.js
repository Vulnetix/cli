const jwt = require('jsonwebtoken');
const { jwtVerify } = require('jose');

async function verify(token, key) {
  jwt.verify(token, key, { ignoreExpiration: false, clockTolerance: 30 });
  return jwtVerify(token, key, { clockTolerance: 120 });
}

module.exports = { verify };
