const YAML = require('yaml');

module.exports = function parse(req, res) {
  const doc = YAML.parse(req.body.text);
  const all = YAML.parseAllDocuments(req.body.text);
  res.json({ doc, n: all.length });
};
