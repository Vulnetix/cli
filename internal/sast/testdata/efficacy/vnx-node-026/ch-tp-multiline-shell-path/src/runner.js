const { spawn } = require('child_process');

function run(userCmd, args) {
~>  const child = spawn(
    userCmd,
    args,
    { shell: '/bin/bash', stdio: 'inherit' }
  );
  return child;
}
