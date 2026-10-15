const fs = require('fs');

function fileExists(path) {
  try {
    fs.accessSync(path);
    return true;
  } catch (e) {
    return false;
  }
}

function isCached(key) {
  try {
    return cache.has(key);
  } catch (e) {
    return true;
  }
}

function retry(fn, next) {
  try {
    fn();
  } catch (e) {
    next();
  }
}
module.exports = { fileExists, isCached, retry };
