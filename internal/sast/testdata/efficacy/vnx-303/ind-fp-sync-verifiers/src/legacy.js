const bcrypt = require('bcryptjs');

function loginSync(user, password) {
  if (user && bcrypt.compareSync(password, user.passwordHash)) {
    return user;
  }
  return null;
}

module.exports = { loginSync };
