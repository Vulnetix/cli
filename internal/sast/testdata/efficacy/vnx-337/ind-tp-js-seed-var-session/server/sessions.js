const seedrandom = require('seedrandom');

const seed = Date.now();
~>const rng = seedrandom(String(seed));

function newSessionId() {
  let sessionId = '';
  for (let i = 0; i < 24; i++) {
    sessionId += Math.floor(rng() * 16).toString(16);
  }
  return sessionId;
}

module.exports = { newSessionId };
