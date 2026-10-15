function flatten(grid) {
  var out = [];
  for (var i = 0; i < grid.length; i++) {
    var row = grid[i];
    if (!row) { continue; }
~>    for (var i = 0; i < row.length; i++) {
      out.push(row[i]);
    }
  }
  return out;
}
