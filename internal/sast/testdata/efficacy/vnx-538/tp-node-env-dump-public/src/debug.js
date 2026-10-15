const fs = require('fs');
const path = require('path');

function dumpDiagnostics() {
~>  fs.writeFileSync(path.join(__dirname, 'public', 'debug.json'), JSON.stringify(process.env));
}

module.exports = { dumpDiagnostics };
