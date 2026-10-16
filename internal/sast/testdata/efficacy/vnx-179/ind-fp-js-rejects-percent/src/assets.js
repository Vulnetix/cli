const path = require('path');

function resolveAsset(p) {
  if (p.includes('%') || p.includes('../')) {
    throw new Error('invalid asset path');
  }
  const decoded = decodeURIComponent(p);
  return path.join(__dirname, 'assets', decoded);
}

module.exports = { resolveAsset };
