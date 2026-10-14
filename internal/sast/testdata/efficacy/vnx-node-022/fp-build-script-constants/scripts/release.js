const shell = require('shelljs');
const pkg = require('../package.json');

if (!shell.which('git')) {
  shell.echo('git is required');
  shell.exit(1);
}

shell.exec('npm run build');
shell.exec(`git tag v${pkg.version}`);
shell.exec("git push --tags");
shell.rm('-rf', 'dist/tmp');
