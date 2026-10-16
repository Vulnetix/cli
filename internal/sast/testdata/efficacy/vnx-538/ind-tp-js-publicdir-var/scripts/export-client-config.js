const fs = require('fs');
const path = require('path');
const config = require('../config');

const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');

function exportClientConfig(done) {
  const outFile = path.join(PUBLIC_DIR, 'runtime-config.json');
  const payload = {
    apiBase: config.apiBase,
    apiKey: config.stripeSecretKey,
  };
~>  fs.writeFile(outFile, JSON.stringify({ apiKey: config.apiKey, payload }), done);
}

module.exports = exportClientConfig;
