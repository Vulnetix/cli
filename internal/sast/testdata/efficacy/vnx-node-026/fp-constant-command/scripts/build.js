const { spawn, spawnSync } = require('child_process');
const path = require('path');

const NPM = 'npm';

spawnSync('npm run build', { shell: true, stdio: 'inherit' });
spawn(NPM, ['install', '--no-audit'], { shell: true });
spawn('node', [path.join(__dirname, 'gen.js')], { shell: true, cwd: __dirname });
