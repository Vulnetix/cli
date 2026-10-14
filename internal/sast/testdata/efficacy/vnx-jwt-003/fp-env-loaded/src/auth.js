const jwt = require('jsonwebtoken');

const secret = process.env.JWT_SECRET;
// jwt.sign(payload, 'literal') is how secrets leak; load it instead
const help = "never call jwt.sign(p, 'hardcoded') in production";

function issue(user) {
  return jwt.sign({ sub: user.id, role: 'user' }, secret, { expiresIn: '1h' });
}

function verify(token) {
  return jwt.verify(token, config.get('jwt.secret'), { algorithms: ['HS256'] });
}

module.exports = { issue, verify, help };
