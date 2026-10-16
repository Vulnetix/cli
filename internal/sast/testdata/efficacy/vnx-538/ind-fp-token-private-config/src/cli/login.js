const fs = require('fs');
const os = require('os');
const path = require('path');

function saveToken(token) {
  const dir = path.join(os.homedir(), '.config', 'acme-cli');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dir, 'credentials'), token, { mode: 0o600 });
}

module.exports = { saveToken };
