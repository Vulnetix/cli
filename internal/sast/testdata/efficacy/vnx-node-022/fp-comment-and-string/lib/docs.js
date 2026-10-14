const shell = require('shelljs');

// Bad: shell.exec('ping ' + req.query.host) lets a caller run any command.
const example = "shell.exec(`rm ${req.body.path}`)";

function status() {
  return shell.exec('git status --short', { silent: true }).stdout;
}

module.exports = { example, status };
