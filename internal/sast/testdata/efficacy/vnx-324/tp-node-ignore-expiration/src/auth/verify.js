const jwt = require('jsonwebtoken');

function verifySession(token) {
~>  return jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'], ignoreExpiration: true });
}

function verifyApiToken(token, key) {
  const opts = {
    algorithms: ['HS256'],
~>    ignoreExpiration : true,
  };
  return jwt.verify(token, key, opts);
}

module.exports = { verifySession, verifyApiToken };
