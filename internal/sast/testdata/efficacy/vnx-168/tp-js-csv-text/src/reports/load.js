async function loadReport() {
  const res = await fetch('/exports/orders.csv');
  const text = await res.text();
  return text
    .split('\n')
~>    .map((row) => row.split(','));
}

function parseCsvLine(csvLine) {
~>  const [id, name, amount] = csvLine.split(",");
  return { id, name, amount: Number(amount) };
}

module.exports = { loadReport, parseCsvLine };
