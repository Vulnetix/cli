export function layout(cols: number[][]): number {
  let width = 0;
  for (let c = 0; c < cols.length; c++) {
    const col = cols[c];
    if (col.length === 0) {
      continue;
    }
~>    for (c = 0; c < col.length; c++) {
      width += col[c];
    }
  }
  return width;
}
