const jwt = require('jsonwebtoken');

function read(token, key) {
  return jwt.verify(token, key, { algorithms: ['HS256'] });
}

module.exports = { read };
