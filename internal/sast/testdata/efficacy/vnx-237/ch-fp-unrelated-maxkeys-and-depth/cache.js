const LRU = require("lru-cache");

const cache = new LRU({ max: 500, maxKeys: 0 });
const walkOptions = { depth: Infinity, followSymlinks: false };

function walk(dir) {
  return fsWalk(dir, walkOptions);
}

module.exports = { cache, walk };
