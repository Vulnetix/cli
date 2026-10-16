const { spawn } = require('child_process');

module.exports = function npm(args, cwd) {
  return spawn('npm', args, {
    cwd,
    shell: process.platform === 'win32',
    stdio: 'inherit',
  });
};
