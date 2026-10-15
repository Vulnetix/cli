const jwt = require('jsonwebtoken');
const cache = {};

function sign(id, secret, req, token) {
  const signed = jwt.sign({ sub: id, iat: Math.floor(Date.now() / 1000) }, secret);
  req.session.lastSeen = Date.now();
  cache[token] = Date.now();
  const started = Date.now();
  return signed;
}

module.exports = { sign };
