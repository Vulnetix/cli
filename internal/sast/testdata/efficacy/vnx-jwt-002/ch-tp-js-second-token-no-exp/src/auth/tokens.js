const jwt = require('jsonwebtoken');

function access(u, key) {
  const token = jwt.sign({ sub: u.id }, key, { expiresIn: '15m' });
  return token;
}

function refresh(u, key) {
~>  const token = jwt.sign({ sub: u.id, typ: 'refresh' }, key);
  return token;
}

module.exports = { access, refresh };
