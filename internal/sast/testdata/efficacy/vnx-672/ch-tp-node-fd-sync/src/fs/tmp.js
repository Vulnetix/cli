const fs = require('fs');

function writeTemp(path, buf) {
  const fd = fs.openSync(path, 'w');
  fs.closeSync(fd);
~>  fs.writeSync(fd, buf);
}
