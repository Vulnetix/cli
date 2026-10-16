const jwt = require('jsonwebtoken');

const secret = process.env.JWT_SECRET;
function issue(user) {
  return jwt.sign({ id: user.id }, secret, { expiresIn: '1h' });
}
module.exports = { issue };
