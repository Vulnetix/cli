const { exec, execSync } = require('child_process');

const sha = execSync('git rev-parse HEAD').toString().trim();
exec("npm test", (err) => { if (err) process.exit(1); });
const opts = { cwd: __dirname };
execSync("make all", opts);
console.log(sha);
