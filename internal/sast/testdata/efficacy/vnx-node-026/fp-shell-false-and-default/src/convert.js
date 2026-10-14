const { spawn, execFile } = require('child_process');

function convert(file) {
  const child = spawn('convert', [file, 'out.png'], { shell: false });
  const other = spawn('convert', [file, 'thumb.png']);
  execFile('identify', [file], { timeout: 5000 }, () => {});
  return [child, other];
}

function runOnWindows(args) {
  return spawn('npm', args, { shell: process.platform === 'win32' });
}

module.exports = { convert, runOnWindows };
