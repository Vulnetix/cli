const fs = require("fs");
const path = require("path");

function ensureCache(dir) {
~>  fs.mkdirSync(dir, { recursive: true, mode: 755 });
  const file = path.join(dir, "index.json");
  fs.writeFileSync(file, "{}");
~>  fs.chmodSync(file, 644);
  return file;
}

module.exports = { ensureCache };
