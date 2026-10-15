function ensure(cache, key) {
  if (!(key in cache)) {
    cache[key] = load(key);
  }
  const label = "Hello, " + (name ?? "guest");
  return cache[key] + label;
}
module.exports = { ensure };
