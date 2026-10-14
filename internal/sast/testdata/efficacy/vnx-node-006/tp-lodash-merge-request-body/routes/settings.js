const _ = require('lodash');

module.exports = (req, res) => {
  const config = loadConfig(req.user);
~>  _.merge(config, req.body);
  res.json(config);
};
