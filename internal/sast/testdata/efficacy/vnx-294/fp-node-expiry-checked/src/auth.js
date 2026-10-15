const jwt = require('jsonwebtoken');

function readSession(token) {
  return jwt.verify(token, process.env.JWT_KEY, { ignoreExpiration: false, clockTolerance: 60 });
}
