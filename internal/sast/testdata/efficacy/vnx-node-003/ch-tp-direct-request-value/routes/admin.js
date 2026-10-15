const childProcess = require("child_process");

module.exports = function run(req, res) {
~>  childProcess.exec(req.body.command, (err, stdout) => {
    res.send(stdout);
  });
};

function fromCli() {
~>  return childProcess.execSync(process.argv[2]).toString();
}
