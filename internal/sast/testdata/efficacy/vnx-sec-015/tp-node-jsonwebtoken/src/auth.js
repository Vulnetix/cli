const jwt = require('jsonwebtoken');
const { UnsecuredJWT } = require('jose');

function verify(token) {
~>  return jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });
}

function sign(user) {
~>  return jwt.sign({ sub: user.id }, '', { algorithm: 'none' });
}

const opts = {
~>  algorithms: ["none"],
};

function readUnsigned(token) {
~>  return UnsecuredJWT.decode(token).payload;
}
