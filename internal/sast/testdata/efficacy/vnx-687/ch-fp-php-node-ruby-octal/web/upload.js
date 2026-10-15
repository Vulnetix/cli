const fs = require('fs');

function store(dir, file, data) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  fs.writeFileSync(file, data, { mode: 0o600 });
  fs.chmodSync(file, 0o644);
  setTimeout(() => {}, 500);
  const opts = { timeout: 750 };
  return opts;
}
module.exports = { store };
