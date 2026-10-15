const fs = require("fs");

function prepare(bin) {
  fs.chmodSync(bin, 0o755);
  if (fs.statSync(bin).mode & 0o4000) {
    console.warn(`${bin} is setuid; fs.chmodSync(bin, 0o4755) is not allowed`);
  }
}

module.exports = { prepare };
