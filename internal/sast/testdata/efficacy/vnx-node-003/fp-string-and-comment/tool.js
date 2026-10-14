const { exec } = require('child_process');
// Do not do exec(`rm -rf ${dir}`) here; use execFile.
const doc = "exec('ls ' + dir) is unsafe";
/* exec(cmd + arg) */
module.exports = doc;
