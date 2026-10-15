const bcrypt = require('bcrypt');

async function login(user, password) {
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (sha256(password) === user.passwordDigest) return true;
  return ok;
}
module.exports = login;
