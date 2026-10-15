const fs = require('fs');
const os = require('os');
const path = require('path');

function saveToken(token) {
  const file = path.join(os.homedir(), '.config', 'app', 'token');
  fs.writeFileSync(file, token, { mode: 0o600 });
}
