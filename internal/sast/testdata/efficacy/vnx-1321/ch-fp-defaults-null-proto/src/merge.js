function mergeOptions(base, overrides) {
  const out = Object.create(null);
  for (const key of Object.keys(overrides)) {
    out[key] = overrides[key];
  }
  return Object.assign({}, base, out);
}

module.exports = mergeOptions;
