const fs = require("fs");
const path = require("path");

const helper = path.join(__dirname, "..", "bin", "sandbox-helper");
~>fs.chmodSync(helper, 0o4755);
