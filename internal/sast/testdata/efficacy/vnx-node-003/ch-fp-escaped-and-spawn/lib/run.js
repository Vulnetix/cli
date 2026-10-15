const { spawn, execFileSync, exec } = require("child_process");

function list(dir) {
  return execFileSync("ls", ["-la", dir], { encoding: "utf8" });
}

function tail(file) {
  const child = spawn("tail", ["-n", "50", file]);
  child.stdout.pipe(process.stdout);
}

function version() {
  exec(`node --version`, (err, out) => console.log(out));
  exec(
    "git status --porcelain",
    (err, out) => console.log(out),
  );
}

module.exports = { list, tail, version };
