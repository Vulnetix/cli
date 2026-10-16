const csv = require('./exporters/csv');
const pdf = require('./exporters/pdf');
const { formatGreeting } = require('./greetings');

const EXPORTERS = { csv, pdf };

module.exports = (app) => {
  app.get('/export', (req, res) => {
    const exporter = EXPORTERS[req.query.format];
    if (!exporter) return res.status(400).send('unknown format');
    res.send(exporter.render(req.query.id));
  });

  app.get('/hello', (req, res) => {
    res.send(require('./greetings').for(req.query.name) + formatGreeting(req.query.name));
  });
};
