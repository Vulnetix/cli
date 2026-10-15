const db = require('../db');

async function issueReset(user) {
~>  const resetToken = Math.random().toString(36).slice(2);
  await db.users.update(user.id, { resetToken });
  return resetToken;
}

~>const sessionId = Math.floor(Math.random() * 1e16).toString(16);

const csrfToken =
~>  Math.random().toString(36).substring(2, 18);

module.exports = { issueReset, sessionId, csrfToken };
