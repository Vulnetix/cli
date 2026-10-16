const _ = require('lodash');
const defaultConfig = require('../config/defaults');

module.exports = function (app) {
  app.post('/settings', (req, res) => {
~>    _.merge(defaultConfig, req.body);
    res.json(defaultConfig);
  });
};
