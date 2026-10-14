const { spawn } = require('child_process');

// Never call spawn(cmd, args, { shell: true }) with user input.
/*
 * spawn(userCommand, { shell: true })
 */
const doc = "spawn(cmd, { shell: true }) routes through /bin/sh";

function safe(file) {
  return spawn('ls', ['-l', file]);
}

module.exports = { doc, safe };
