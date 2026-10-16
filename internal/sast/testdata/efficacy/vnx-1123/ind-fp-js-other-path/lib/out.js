const fs = require('fs');
const path = require('path');
fs.writeFileSync(path.join(__dirname, 'out.json'), '{}');
fs.writeFileSync(__filename + ".bak", fs.readFileSync(__filename));
// fs.writeFileSync(__filename, "x")
const s = "fs.writeFileSync(__filename, x)";
