const yaml = require('js-yaml');
module.exports = (req, res) => {
~>  const cfg = yaml.load(req.body.config);
  res.json(cfg);
};
