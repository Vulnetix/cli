const seedrandom = require('seedrandom');

~>const rng = seedrandom(Date.now().toString());

function createSession(user) {
  const sessionId = rng().toString(36).slice(2);
  return { user, sessionId };
}

module.exports = { createSession };
