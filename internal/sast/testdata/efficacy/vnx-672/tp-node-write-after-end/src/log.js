const fs = require('fs');

function writeLog(lines) {
  const stream = fs.createWriteStream('app.log');
  stream.write(lines.join('\n'));
  stream.end();
~>  stream.write('\n-- end --\n');
}

function copy(src, dst) {
  const fd = fs.openSync(src, 'r');
  fs.closeSync(fd);
~>  const n = fs.readSync(fd, buf, 0, 1024, 0);
  return n;
}
