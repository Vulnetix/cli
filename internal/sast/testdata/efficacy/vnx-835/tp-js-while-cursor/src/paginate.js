export function collect(items, max) {
  const out = [];
  let idx = 0;
~>  while (idx < max) {
    out.push(items[idx]);
  }
  return out;
}
