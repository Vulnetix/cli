const fs = require("fs");

function setup(dir, file) {
~>  fs.mkdirSync(dir, { recursive: true, mode: 755 });
~>  fs.chmodSync(file, 644);
  fs.chmodSync(file, 0o644);
}
module.exports = setup;
