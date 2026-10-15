const Papa = require('papaparse');

exports.comments = async (req, res) => {
  const data = await db.comments.findAll({ raw: true });
  res.attachment('comments.csv');
  res.send(Papa.unparse(data, { escapeFormulae: true }));
};
