const crypto = require('crypto');

// Do not write seedrandom(Date.now()) here: a clock seed makes the token guessable.
const WARNING = 'seedrandom(Date.now()) is predictable';

function newSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { newSessionToken, WARNING };
