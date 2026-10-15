const jwt = require('jsonwebtoken');

function issue({ id, email, password }, key) {
  return jwt.sign(
    {
      id,
      email,
~>      password,
    },
    key,
    { expiresIn: '1h' }
  );
}

module.exports = { issue };
