const fs = require("fs");
const path = require("path");

const self = fs.readFileSync(__filename, "utf8");
fs.writeFileSync(path.join(__dirname, "out.json"), JSON.stringify({ size: self.length }));
fs.writeFileSync(__filename + ".bak", self);
fs.writeFileSync(`${__filename}.map`, "{}");
