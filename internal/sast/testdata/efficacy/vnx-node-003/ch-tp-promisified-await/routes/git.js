const util = require("util");
const execAsync = util.promisify(require("child_process").exec);

module.exports = async function log(req, res) {
  const { branch } = req.params;
~>  const { stdout } = await execAsync(`git log --oneline ${branch}`);
  res.type("text").send(stdout);
};
