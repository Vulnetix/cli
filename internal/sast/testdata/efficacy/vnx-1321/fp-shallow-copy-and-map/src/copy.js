function shallowCopy(dst, src) {
  for (const key in src) {
    dst[key] = src[key];
  }
  return dst;
}

function countBy(items) {
  const counts = new Map();
  for (const item of items) {
    counts.set(item.kind, (counts.get(item.kind) || 0) + 1);
  }
  return counts;
}

function index(rows) {
  const out = {};
  rows.forEach((row) => {
    out[row.id] = row;
  });
  return out;
}

module.exports = { shallowCopy, countBy, index };
