module.exports = function exportRows(req, res) {
  res.setHeader('Content-Type', 'text/csv');
  for (const row of rows) {
    res.write(row.join(',') + '\n');
  }
  res.end();
};
