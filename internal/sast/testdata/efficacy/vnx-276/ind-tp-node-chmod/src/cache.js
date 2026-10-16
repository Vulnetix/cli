const fs = require('fs');
const path = require('path');

function ensureCache(dir) {
  fs.mkdirSync(dir, { recursive: true });
~>  fs.chmodSync(dir, 0o777);
  const sock = path.join(dir, 'worker.sock');
~>  fs.chmod(sock, '666', (err) => {
    if (err) console.error(err);
  });
}

module.exports = { ensureCache };
