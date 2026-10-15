const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function login(res, sub, secret) {
  const token = jwt.sign({ sub, iat: Math.floor(Date.now() / 1000) }, secret);
  const sid = crypto.randomBytes(24).toString('base64url');
  res.cookie('session', sid, { maxAge: 3600000, expires: new Date(Date.now() + 3600000) });
  return token;
}

module.exports = { login };
