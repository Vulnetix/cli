const fs = require('fs');

const SUNSET = new Date('2026-06-30');

function notice(file) {
  if (Date.now() > SUNSET.getTime()) {
    console.warn('This API version is past its sunset date');
  }
  if (Date.now() - fs.statSync(file).mtimeMs > 7 * 24 * 3600 * 1000) {
    fs.unlinkSync(file);
  }
}

module.exports = notice;
