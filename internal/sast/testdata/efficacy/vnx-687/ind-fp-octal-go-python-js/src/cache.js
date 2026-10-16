const fs = require("fs");

function ensureCache(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  fs.chmodSync(dir, 0o700);
}

module.exports = { ensureCache };
