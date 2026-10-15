const yaml = require('js-yaml');

module.exports = function saveConfig(req, res) {
~>  const cfg = yaml.load(req.body.config);
  res.json(cfg);
};
