const { spawn, execFile } = require('child_process');

function run(cmd, args) {
  return spawn(cmd, args, { shell: false, stdio: 'pipe' });
}
function run2(userFile) {
  return spawn('cat', [userFile]);
}
function run3(userFile) {
  execFile('wc', ['-l', userFile], (err, out) => console.log(out));
}
module.exports = { run, run2, run3 };
