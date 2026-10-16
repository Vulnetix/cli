const shell = require('shelljs');
const pkg = require('../package.json');
shell.exec('git add -A');
shell.exec('git tag v' + pkg.version);
shell.exec('npm publish');
