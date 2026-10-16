const jwt = require('jsonwebtoken');

function check(token) {
  return jwt.verify(token, process.env.JWT_KEY, { algorithms: ['HS256'] });
}
module.exports = { check };
