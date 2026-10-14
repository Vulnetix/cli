const jwt = require('jsonwebtoken');

function verify(token) {
  return jwt.verify(token, process.env.SESSION_KEY, { algorithms: ['HS256'] });
}

module.exports = { verify };
