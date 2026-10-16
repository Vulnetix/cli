const argon2 = require('argon2');

async function login(db, username, password) {
  const row = await db.one('SELECT id, pw_hash FROM users WHERE username = $1', [username]);
~>  const valid = argon2.verify(row.pw_hash, password);
  if (!valid) {
    throw new Error('bad password');
  }
  return issueSession(row.id);
}

module.exports = { login };
