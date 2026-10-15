function ensure(cache, key) {
~>  if (!key in cache) {
    cache[key] = load(key);
  }
  return cache[key];
}
module.exports = { ensure };
