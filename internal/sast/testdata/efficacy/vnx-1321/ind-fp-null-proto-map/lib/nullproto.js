function build(entries) {
  const out = Object.create(null);
  for (const [k, v] of entries) {
    out[k] = v;
  }
  return out;
}

const registry = new Map();
function register(req) {
  registry.set(req.body.section, req.body.value);
}
module.exports = { build, register };
