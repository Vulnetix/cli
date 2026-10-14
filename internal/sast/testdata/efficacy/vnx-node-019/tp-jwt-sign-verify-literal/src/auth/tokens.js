const jwt = require('jsonwebtoken');

function issue(user) {
~>  return jwt.sign({ sub: user.id, role: user.role }, 'sup3r-s3cret-signing-key', { expiresIn: '1h' });
}

function check(token) {
~>  return jwt.verify(token, "sup3r-s3cret-signing-key");
}

function refresh(user) {
~>  return jwt.sign(
    { sub: user.id },
    `refresh-key-2024`,
    { expiresIn: '7d' },
  );
}

module.exports = { issue, check, refresh };
