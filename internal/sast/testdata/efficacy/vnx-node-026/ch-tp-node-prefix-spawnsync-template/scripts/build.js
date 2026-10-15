const cp = require('node:child_process');

function listDir(dir) {
~>  return cp.spawnSync(`ls -la ${dir}`, { shell: true, encoding: 'utf8' }).stdout;
}
module.exports = listDir;
