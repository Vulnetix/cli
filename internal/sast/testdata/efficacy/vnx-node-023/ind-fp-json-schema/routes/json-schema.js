const yaml = require('js-yaml');
module.exports = (req, res) => {
  const a = yaml.load(req.body.config, { schema: yaml.JSON_SCHEMA });
  const b = yaml.load(req.body.other, { schema: yaml.CORE_SCHEMA });
  res.json([a, b]);
};
