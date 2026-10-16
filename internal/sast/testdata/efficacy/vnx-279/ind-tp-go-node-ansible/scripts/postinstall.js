const fs = require('fs');
const path = require('path');

const sandbox = path.join(__dirname, '..', 'dist', 'chrome-sandbox');
~>fs.chmodSync(sandbox, 0o4755);
