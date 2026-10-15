function flatten(grid) {
  const out = [];
  for (let i = 0; i < grid.length; i++) {
    for (let i = 0; i < 2; i++) {
      out.push(i);
    }
  }
  return out;
}
