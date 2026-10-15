const { promisify } = require("node:util");
const { execFile } = require("node:child_process");
const execFileAsync = promisify(execFile);

async function log(branch) {
  const { stdout } = await execFileAsync("git", ["log", "--oneline", branch]);
  return stdout;
}

async function show(ref) {
  return execFileAsync("git", ["show", `${ref}:package.json`]);
}

module.exports = { log, show };
