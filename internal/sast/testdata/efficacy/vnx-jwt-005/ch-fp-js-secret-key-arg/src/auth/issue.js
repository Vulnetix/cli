const jwt = require('jsonwebtoken');

function issue(user, secret) {
  return jwt.sign({ id: user.id, role: user.role }, secret, { expiresIn: '1h' });
}

module.exports = { issue };
