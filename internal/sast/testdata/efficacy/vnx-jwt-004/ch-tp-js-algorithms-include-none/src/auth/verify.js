const jwt = require('jsonwebtoken');

function verify(token, key) {
~>  return jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
}

module.exports = { verify };
