const yaml = require('js-yaml');
module.exports = (req, res) => {
  const cfg = yaml.safeLoad(req.body.config);
  res.json(cfg);
};
