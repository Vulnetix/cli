const { spawnSync, spawn } = require('child_process');

spawnSync('npm run build', { shell: true, stdio: 'inherit' });
spawn('rimraf', ['dist'], { shell: true });
