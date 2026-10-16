const jwt = require('jsonwebtoken');

function issue(user) {
  return jwt.sign({ id: user.id }, process.env.JWT_KEY, { expiresIn: '15m' });
}
module.exports = { issue };
