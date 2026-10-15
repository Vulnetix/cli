const bcrypt = require("bcryptjs");

function login(user, password) {
~>  bcrypt.compareSync(password, user.passwordHash);
  return createSession(user);
}

module.exports = { login };
