'use strict';
const jwt = require('jsonwebtoken');

// Never set ignoreExpiration: true here; refresh tokens have their own endpoint.
function readSession(token, secret) {
  return jwt.verify(token, secret, {
    algorithms: ['HS256'],
    ignoreExpiration: false,
    clockTolerance: 5,
  });
}

module.exports = { readSession };
