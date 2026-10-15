const shell = require('shelljs');

const version = require('../package.json').version;

if (shell.exec('npm test').code !== 0) {
  shell.echo('tests failed');
  shell.exit(1);
}
shell.exec(`git tag v${version}`);
shell.exec('git push --tags');
