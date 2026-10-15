const fs = require('fs');

function cleanup(path, fd) {
  fs.closeSync(fd);
  fs.unlinkSync(path);
  console.log('removed', path);
}

function stop(server, pool) {
  server.close();
  pool.end();
  logger.write('stopped');
}
