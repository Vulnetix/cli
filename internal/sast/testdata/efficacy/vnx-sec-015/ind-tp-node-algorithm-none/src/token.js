const jwt = require('jsonwebtoken');

function issue(payload) {
~>  return jwt.sign(payload, '', { algorithm: 'none' });
}

module.exports = { issue };
