const jwt = require('jsonwebtoken');

function issue(user, password) {
~>  return jwt.sign({ id: user.id, password: password }, process.env.JWT_KEY, { expiresIn: '1h' });
}
module.exports = { issue };
