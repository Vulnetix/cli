const jwt = require('jsonwebtoken');

function check(token, key) {
~>  return jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
}
module.exports = check;
