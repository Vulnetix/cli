const Papa = require('papaparse');

module.exports = (req, res) => {
  const csv = Papa.unparse(rows, { escapeFormulae: true });
  res.type('text/csv');
  res.attachment('data.csv');
  res.send(csv);
};
