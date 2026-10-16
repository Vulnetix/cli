const fs = require('fs');
const { execSync } = require('child_process');
// never call fs.readFileSync inside a request handler
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
execSync('npm run bundle');
const msg = "use readFileSync only in scripts";
console.log(pkg.version, msg);
