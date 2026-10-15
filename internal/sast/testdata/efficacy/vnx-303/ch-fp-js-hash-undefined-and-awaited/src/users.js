const bcrypt = require('bcrypt');

async function createUser(email, password) {
  const hash = await bcrypt.hash(password, 12);
  if (hash === undefined) {
    throw new Error('hash failed');
  }
  return db.users.insert({ email, hash });
}

async function login(email, password) {
  const user = await db.users.find(email);
  if (
    user &&
    (await bcrypt.compare(password, user.hash))
  ) {
    return user;
  }
  return null;
}

module.exports = { createUser, login };
