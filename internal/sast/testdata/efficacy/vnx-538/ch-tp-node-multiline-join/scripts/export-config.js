const fs = require('fs');
const path = require('path');

function exportClientConfig(cfg) {
~>  fs.writeFileSync(path.join(__dirname, '..', 'public', 'config.json'),
    JSON.stringify({ apiUrl: cfg.apiUrl, apiKey: cfg.apiKey }));
}

module.exports = { exportClientConfig };
