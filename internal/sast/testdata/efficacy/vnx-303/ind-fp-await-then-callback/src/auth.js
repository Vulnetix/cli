const bcrypt = require('bcrypt');
const argon2 = require('argon2');

async function loginAwait(user, password) {
  if (user && await bcrypt.compare(password, user.passwordHash)) {
    return true;
  }
  const ok = await argon2.verify(user.argonHash, password);
  if (!ok) return false;
  return true;
}

function loginThen(user, password, done) {
  bcrypt.compare(password, user.passwordHash).then((match) => {
    if (match) done(null, user);
    else done(null, false);
  });
}

function loginCallback(user, password, done) {
  bcrypt.compare(password, user.passwordHash, (err, match) => {
    if (err || !match) return done(null, false);
    return done(null, user);
  });
}

module.exports = { loginAwait, loginThen, loginCallback };
