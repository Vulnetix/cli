const jwt = require('jsonwebtoken');

function verifySession(token, key) {
  return jwt.verify(token, key, { algorithms: ['RS256'], ignoreExpiration: false, clockTolerance: 30 });
}

const allowLegacy = process.env.ALLOW_LEGACY === '1';
function verifyLegacy(token, key) {
  return jwt.verify(token, key, { ignoreExpiration: allowLegacy && false });
}

module.exports = { verifySession, verifyLegacy };
