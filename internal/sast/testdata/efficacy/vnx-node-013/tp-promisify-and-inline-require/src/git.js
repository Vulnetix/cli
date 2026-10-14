const util = require('util');
const { exec: run } = require('child_process');

const execAsync = util.promisify(require('child_process').exec);

async function checkout(req, res) {
  const branch = req.body.branch;
~>  await execAsync(`git checkout ${branch}`);
  res.sendStatus(204);
}

function show(req, res) {
~>  require('child_process').exec('git show ' + req.params.sha, (e, out) => res.send(out));
}

function blame(req, res) {
~>  run('git blame ' + req.query.file, (e, out) => res.send(out));
}

module.exports = { checkout, show, blame };
