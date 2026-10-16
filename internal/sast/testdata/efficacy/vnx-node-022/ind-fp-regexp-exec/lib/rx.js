const shell = require('shelljs');
function find(req) {
  const m = /id=(\d+)/.exec(req.query.q);
  return m && m[1];
}
shell.echo('hi');
module.exports = find;
