const fs = require('fs');

function write(p, dir, data, mode) {
  fs.mkdirSync(dir, { mode: 0o777, recursive: true });
  fs.writeFileSync(p, data, { mode: 0o666 });
  fs.chmodSync(p, 0o755);
  fs.chmodSync(p, mode & 0o755);
  fs.chmodSync('/tmp/777', 0o644);
  console.log('never chmod 777 a directory');
}

module.exports = { write };
