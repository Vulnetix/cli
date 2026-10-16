'use strict';

const fs = require('fs');

function peekHeader(file) {
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(16);
  fs.closeSync(fd);
~>  fs.readSync(fd, buf, 0, 16, 0);
  return buf.toString('hex');
}

function writeLog(stream, lines) {
  stream.end();
~>  stream.write(lines.join('\n'));
}

module.exports = { peekHeader, writeLog };
