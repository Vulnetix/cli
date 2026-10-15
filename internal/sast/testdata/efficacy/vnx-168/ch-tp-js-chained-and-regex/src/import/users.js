const fs = require('fs');

function loadUsers(csvPath) {
  const rows = fs.readFileSync(csvPath, 'utf8').trim().split('\n');
  return rows.slice(1).map((row) => {
    const cols = row
~>      .split(',');
    return { name: cols[0], email: cols[1], role: cols[2] };
  });
}

function loadOrders(text) {
  // text is the body of an uploaded orders.csv
~>  return text.split('\n').map((line) => line.split(/,/));
}

module.exports = { loadUsers, loadOrders };
