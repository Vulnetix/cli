const fs = require('fs');

function openCache(dir) {
  fs.mkdirSync(dir, { recursive: true });
~>  fs.chmodSync(dir, '777');
  return dir;
}

module.exports = { openCache };
