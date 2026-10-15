const crypto = require("crypto");
const bcrypt = require("bcrypt");

async function login(user, password) {
  if (await bcrypt.compare(password, user.passwordHash)) {
    return true;
  }
  const a = Buffer.from(user.password);
  const b = Buffer.from(password);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function hasPassword(user) {
  return user.password !== undefined && user.password !== null && user.password.length === 0;
}

module.exports = { login, hasPassword };
