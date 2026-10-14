const jwt = require('jsonwebtoken');

function issue(user) {
~>  return jwt.sign({ sub: user.id }, '', { algorithm: 'none' });
}

function read(token, key) {
~>  return jwt.verify(token, key, { algorithms: ['RS256', "none"] });
}

const verifyOptions = {
  issuer: 'shop',
~>  algorithms: [
    'HS256',
    'none',
  ],
};

module.exports = { issue, read, verifyOptions };
