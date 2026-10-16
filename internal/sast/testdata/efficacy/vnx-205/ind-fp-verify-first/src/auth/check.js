const bcrypt = require('bcrypt');

const FALLBACK = '$2b$10$abcdefghijklmnopqrstuuJ8m0Wq9yVY5Zl8nO1nTq1rBMHuW1yUu';

async function verifyLogin(users, email, password) {
  const user = await users.findByEmail(email);
  const ok = await bcrypt.compare(password, user ? user.passwordHash : FALLBACK);
  if (!user) {
    return null;
  }
  return ok ? user : null;
}

module.exports = { verifyLogin };
