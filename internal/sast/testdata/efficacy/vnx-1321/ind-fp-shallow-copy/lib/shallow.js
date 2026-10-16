function copyDefaults(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}
module.exports = copyDefaults;
