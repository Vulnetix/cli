const fs = require("fs");
// fs.chmodSync(file, 644);
fs.mkdirSync("d", { mode: 0o755 });
fs.chmodSync("f", 0o600);
const size = 755;
console.log("chmod 755 is shell");
