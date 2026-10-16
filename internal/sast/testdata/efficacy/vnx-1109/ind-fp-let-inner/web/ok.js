function pairs(a, b) {
  const out = [];
  for (let i = 0; i < a.length; i++) {
    for (let i = 0; i < b.length; i++) {
      out.push([a[i], b[i]]);
    }
  }
  return out;
}
