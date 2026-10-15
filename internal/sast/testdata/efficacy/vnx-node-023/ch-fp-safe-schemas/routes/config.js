const yaml = require('js-yaml');

module.exports = function saveConfig(req, res) {
  const a = yaml.safeLoad(req.body.config);
  const b = yaml.load(req.body.other, { schema: yaml.JSON_SCHEMA });
  const c = yaml.load(req.body.third, { schema: yaml.FAILSAFE_SCHEMA });
  res.json({ a, b, c });
};
