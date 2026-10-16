const fs = require('fs');
const path = require('path');

function loadSales(dir) {
  const raw = fs.readFileSync(path.join(dir, 'sales-report.csv'), 'utf8');
  const [header, ...rows] = raw.trim().split('\n');
~>  const columns = header.split(',');
  return rows.map((row) => {
~>    const values = row.split(',');
    const record = {};
    columns.forEach((c, i) => {
      record[c] = values[i];
    });
    return record;
  });
}

module.exports = { loadSales };
