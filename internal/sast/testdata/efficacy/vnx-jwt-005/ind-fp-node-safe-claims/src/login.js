const jwt = require('jsonwebtoken');

function issue(user) {
  return jwt.sign({ id: user.id, role: user.role, passwordChangedAt: user.pwChangedAt }, process.env.JWT_KEY, { expiresIn: '1h' });
}
module.exports = { issue };
