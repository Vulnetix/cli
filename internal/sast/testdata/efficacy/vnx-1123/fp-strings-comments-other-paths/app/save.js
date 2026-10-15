const fs = require('fs');
const path = require('path');

// fs.writeFileSync(__filename, src)
fs.writeFileSync(path.join(__dirname, 'out.json'), '{}');
fs.writeFileSync(__filename + '.bak', fs.readFileSync(__filename));
console.log("fs.writeFileSync(__filename, x) is not allowed");
