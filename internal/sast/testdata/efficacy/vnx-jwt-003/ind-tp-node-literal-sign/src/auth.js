const jwt = require('jsonwebtoken');

function issue(user) {
~>  return jwt.sign({ id: user.id }, 'my-app-signing-secret-2020', { expiresIn: '1h' });
}
module.exports = { issue };
