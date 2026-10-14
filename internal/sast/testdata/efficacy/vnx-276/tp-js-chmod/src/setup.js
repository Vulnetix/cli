const fs = require('fs');
const fsp = require('fs/promises');
const { execSync } = require('child_process');

async function prepare(dir, sock, logFile) {
~>  fs.chmodSync(dir, 0o777);
~>  await fsp.chmod(logFile, '666');
~>  fs.chmod(sock, 0o777, (err) => {
    if (err) throw err;
  });
~>  execSync(`chmod -R 777 ${dir}`);
}

module.exports = { prepare };
