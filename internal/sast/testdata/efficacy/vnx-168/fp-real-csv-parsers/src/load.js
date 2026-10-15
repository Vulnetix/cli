const Papa = require('papaparse');

async function loadReport() {
  const res = await fetch('/exports/orders.csv');
  const { data } = Papa.parse(await res.text());
  const cols = 'id,name'.split(',');
  return { data, cols };
}

module.exports = { loadReport };
