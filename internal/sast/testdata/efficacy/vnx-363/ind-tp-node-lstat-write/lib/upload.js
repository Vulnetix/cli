'use strict';
const fs = require('fs');

function storeUpload(destPath, buffer) {
  const st = fs.lstatSync(destPath);
  if (st.isSymbolicLink()) {
    throw new Error('destination is a symlink');
  }
~>  fs.writeFileSync(destPath, buffer, { mode: 0o600 });
}

module.exports = { storeUpload };
