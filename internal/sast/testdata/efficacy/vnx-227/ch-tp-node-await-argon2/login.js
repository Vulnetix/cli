const argon2 = require("argon2");

async function login(user, password) {
~>  await argon2.verify(user.hash, password);
  return issueToken(user);
}
module.exports = { login };
