const crypto = require('crypto');

function pickKey(keys) {
  const keyIndex = Math.floor(Math.random() * keys.length);
  return keys[keyIndex];
}

function color() {
  const colors = ['red', 'green', 'blue'];
  return colors[Math.floor(Math.random() * 3)];
}

function sessionToken() {
  const sessionToken = crypto.randomBytes(32).toString('hex');
  return sessionToken;
}

module.exports = { pickKey, color, sessionToken };
