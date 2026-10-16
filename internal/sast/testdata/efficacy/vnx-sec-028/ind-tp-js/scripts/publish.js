const { execSync } = require('child_process');
~>const token = 'npm_@@sample:[A-Za-z0-9]{36}@@';
execSync(`npm publish`, { env: { ...process.env, NPM_TOKEN: token } });
