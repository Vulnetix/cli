function chunk(items, size) {
  const out = [];
  let n = 0;
  for (let i = 0; i < items.length; i++) {
    if (i % size === 0) {
      out.push([]);
      n += 1;
    }
    out[n - 1].push(items[i]);
  }
  return out;
}

module.exports = { chunk };
