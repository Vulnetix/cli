const childProcess = require('child_process');

function grep(pattern, dir) {
~>  return childProcess.execFileSync('grep', ['-r', pattern, dir], { shell: '/bin/bash', encoding: 'utf8' });
}

function archive(name) {
~>  childProcess.execFile('tar', ['-czf', `${name}.tgz`, name], { shell: true }, (err) => {
    if (err) throw err;
  });
}

function lint(target) {
~>  return childProcess.spawnSync(`eslint ${target}`, { shell: true, stdio: 'pipe' });
}

module.exports = { grep, archive, lint };
