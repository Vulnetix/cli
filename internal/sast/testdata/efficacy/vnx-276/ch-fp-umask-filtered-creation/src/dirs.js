const fs = require("fs");

function prepare(dir, file, data) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o777 });
  fs.writeFileSync(file, data, { mode: 0o666 });
}

module.exports = { prepare };
