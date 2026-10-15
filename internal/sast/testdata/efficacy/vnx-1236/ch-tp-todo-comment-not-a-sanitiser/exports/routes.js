const { stringify } = require('csv-stringify/sync');

// TODO: sanitize formula cells before this goes to customers
async function exportLeads(req, res) {
  const leads = await req.db.leads.findAll({ where: { ownerId: req.user.id } });
~>  const body = stringify(leads.map((l) => [l.name, l.company, l.comment]));
  res.attachment(`leads-${req.user.id}.csv`);
  res.send(body);
}

module.exports = { exportLeads };
