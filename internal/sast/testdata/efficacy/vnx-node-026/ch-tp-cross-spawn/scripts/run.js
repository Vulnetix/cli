const spawn = require('cross-spawn');

module.exports = function run(script, extra) {
~>  return spawn('npm', ['run', script, ...extra], { shell: true, stdio: 'inherit' });
};
