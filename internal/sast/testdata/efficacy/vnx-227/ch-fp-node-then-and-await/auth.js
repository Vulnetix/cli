const bcrypt = require("bcrypt");

async function login(user, password) {
  const same = await bcrypt.compare(password, user.hash);
  if (!same) throw new Error("bad password");
  return user;
}

function loginLegacy(user, password, done) {
  bcrypt.compare(password, user.hash).then((ok) => {
    done(ok ? null : new Error("bad password"), user);
  });
}

module.exports = { login, loginLegacy };
