const { spawn, spawnSync } = require('child_process');

spawn('npm', ['run', 'build'], { shell: true, stdio: 'inherit' });
spawnSync('git describe --tags --abbrev=0', { shell: true });
