const { spawn } = require('node:child_process');

const spawnOptions = {
  stdio: 'inherit',
  shell: true,
};

function run(cmd, args) {
~>  return spawn(cmd, args, spawnOptions);
}

module.exports = run;
