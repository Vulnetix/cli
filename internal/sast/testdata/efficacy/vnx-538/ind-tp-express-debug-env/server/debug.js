'use strict';
const fs = require('fs');
const path = require('path');

function dumpDiagnostics(app) {
  if (process.env.ENABLE_DIAG !== '1') {
    return;
  }
  const stamp = new Date().toISOString();
~>  fs.writeFileSync(path.join(__dirname, '..', 'public', 'diag.json'), JSON.stringify({ stamp, env: process.env }, null, 2));
  app.locals.diagWritten = stamp;
}

module.exports = { dumpDiagnostics };
