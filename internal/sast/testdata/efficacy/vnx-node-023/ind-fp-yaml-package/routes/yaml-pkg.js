const YAML = require('yaml');
module.exports = (req, res) => {
  res.json(YAML.parse(req.body.config));
};
