const yaml = require('js-yaml');
module.exports = (req, res) => {
  res.json(yaml.load(req.body.config));
};
