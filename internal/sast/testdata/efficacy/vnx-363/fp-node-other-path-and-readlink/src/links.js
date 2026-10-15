const fs = require('fs');

function resolve(file, out) {
  if (fs.lstatSync(file).isSymbolicLink()) {
    return fs.readlinkSync(file);
  }
  fs.writeFileSync(out, 'x');
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW);
  return fd;
}

module.exports = { resolve };
