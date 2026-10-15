const jwt = require('jsonwebtoken');

function resetToken(user, secret) {
  return jwt.sign(
    { sub: user.id, purpose: 'password_reset', passwordChangedAt: user.passwordChangedAt },
    secret,
    { expiresIn: '15m' }
  );
}

module.exports = { resetToken };
