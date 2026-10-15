const { spawn, execFile } = require('child_process');

function run(cmd, args) {
  spawn(cmd, args, { shell: false });
  execFile(cmd, args, (err, out) => console.log(out));
  return spawn(cmd, args, { shell: process.platform === 'win32' });
}
