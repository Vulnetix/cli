const jwt = require('jsonwebtoken');

function issue(user) {
~>  return jwt.sign({ sub: user.id }, 'super-secret-signing-key', { expiresIn: '1h' });
}
module.exports = issue;
