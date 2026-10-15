const { execSync } = require("child_process");

const INSTALL = "npm ci --ignore-scripts";
const buildCmd = "npm run build";
execSync(INSTALL, { stdio: "inherit" });
execSync(buildCmd, { stdio: "inherit" });
console.log("Run `exec(" + "cmd" + ")` only with constants");
