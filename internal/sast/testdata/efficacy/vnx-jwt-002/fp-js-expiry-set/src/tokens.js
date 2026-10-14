const jwt = require('jsonwebtoken');

const SIGN_OPTIONS = { algorithm: 'RS256', expiresIn: '15m' };

// jwt.sign(payload, key) without expiresIn would never expire
function access(user, key) {
  return jwt.sign({ sub: user.id }, key, { expiresIn: '15m' });
}

function refresh(user, key) {
  return jwt.sign({ sub: user.id, exp: Math.floor(Date.now() / 1000) + 86400 }, key);
}

function service(user, key) {
  return jwt.sign({ sub: user.id }, key, SIGN_OPTIONS);
}

function check(token, key) {
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}

const doc = 'call jwt.sign(payload, key) with an expiry';

module.exports = { access, refresh, service, check, doc };
