const jwt = require('jsonwebtoken');

function readSession(token) {
  // refresh flow: accept old tokens so the client can trade them in
~>  return jwt.verify(token, process.env.JWT_KEY, { algorithms: ['HS256'], ignoreExpiration: true });
}

module.exports = { readSession };
