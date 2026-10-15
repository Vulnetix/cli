const fs = require('fs');

function save(path, body) {
  fs.writeFileSync(path, body, { mode: 0o666 });
  fs.chmodSync(path, 0o644);
  fs.chmod(path, 0o755, () => {});
}

module.exports = { save };
