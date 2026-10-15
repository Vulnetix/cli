const crypto = require('crypto');

const token = crypto.randomBytes(32).toString('hex');
const requestId = crypto.randomUUID();
const colours = ['red', 'green', 'blue'];

function pickColour() {
  return colours[Math.floor(Math.random() * colours.length)];
}

function scheduleRetry(fn) {
  const wait = 1000 + Math.random() * 250;
  setTimeout(fn, wait);
}

const tokenCount = Math.floor(Math.random() * 10);
// const sessionToken = Math.random().toString(36);
const warning = "Never derive a token from Math.random()";
const id = 'chart-' + Math.random().toString(36).slice(2);

module.exports = { token, requestId, pickColour, scheduleRetry, tokenCount, warning, id };
