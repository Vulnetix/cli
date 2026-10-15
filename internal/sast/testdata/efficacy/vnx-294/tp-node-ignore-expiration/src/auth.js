const jwt = require('jsonwebtoken');

function readSession(token) {
~>  return jwt.verify(token, process.env.JWT_KEY, { ignoreExpiration: true });
}

function readRefresh(token) {
  return jwt.verify(token, publicKey, {
    algorithms: ['RS256'],
~>    ignoreExpiration : true,
  });
}

const verifier = {
~>  clockTolerance: 31536000,
};
