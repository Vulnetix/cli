const jwt = require('jsonwebtoken');
const config = require('../config');
function issue(user) {
  return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
}
function verify(t) {
  return jwt.verify(t, config.jwt.secret);
}
module.exports = { issue, verify };
