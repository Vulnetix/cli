const bcrypt = require('bcrypt');

// if (bcrypt.compare(pw, hash)) was the old bug; always await it.
function passwordMatches(user, password) {
  return bcrypt.compare(password, user.passwordHash);
}

async function createUser(repo, email, password) {
  const passwordHash = await bcrypt.hash(password, 12);
  return repo.insert({ email, passwordHash });
}

module.exports = { passwordMatches, createUser };
