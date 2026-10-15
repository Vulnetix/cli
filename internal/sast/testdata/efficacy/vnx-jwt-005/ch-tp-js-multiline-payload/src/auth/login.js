const jwt = require('jsonwebtoken');

function issue(user) {
  return jwt.sign(
    {
      id: user.id,
~>      password: user.password,
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

module.exports = { issue };
