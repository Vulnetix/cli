const fs = require('fs');
const config = require('./config');

exports.page = (req, res) => {
  res.sendFile(req.params.page, { root: 'public' });
};

exports.settings = (req, res) => {
  const raw = fs.readFileSync(config.settingsPath, 'utf8');
  res.type('json').send(raw);
};
