const { exec, execSync } = require('child_process');
const { quote } = require('shell-quote');

exec('npm run build', (err) => { if (err) throw err; });
const sha = execSync('git rev-parse HEAD').toString().trim();
execSync(`tar -czf dist-${sha}.tgz dist`);

function list(req, res) {
  const dir = req.query.dir;
  exec('ls -la ' + quote([dir]), (err, out) => res.send(out));
}

module.exports = { list };
