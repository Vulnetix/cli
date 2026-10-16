const { Parser } = require('json2csv');

module.exports = async (req, res) => {
  const items = await Ticket.find({ owner: req.user.id }).lean();
  const parser = new Parser({ fields: ['title', 'description'] });
~>  const csv = parser.parse(items);
  res.header('Content-Type', 'text/csv');
  res.attachment('tickets.csv');
  res.send(csv);
};
