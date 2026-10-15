const fs = require('fs');

const SUNSET = new Date('2026-06-30');

function maybeWarn(tmp) {
  if (Date.now() > SUNSET.getTime()) {
    console.warn('v1 API is retired; switch to v2');
  }
  fs.rmSync(tmp, { force: true });
  const now = Date.now();
  if (now > SUNSET.getTime()) throw new Error('v1 API is retired');
}

module.exports = maybeWarn;
