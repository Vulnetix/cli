const fs = require('fs');

function head(path) {
  const fd = fs.openSync(path, 'r');
  const buf = Buffer.alloc(16);
  fs.closeSync(fd);
~>  fs.readSync(fd, buf, 0, 16, 0);
  return buf;
}
module.exports = head;
