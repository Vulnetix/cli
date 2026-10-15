const fs = require('fs');

function publishStats(n, words) {
  fs.writeFileSync('public/stats.json', JSON.stringify({ tokenCount: n, words }));
}

module.exports = { publishStats };
