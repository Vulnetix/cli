const express = require('express');
const router = express.Router();
const PLUGINS = {
  csv: require('./plugins/csv'),
  json: require('./plugins/json'),
};
const loaders = new Map([['csv', './plugins/csv']]);

router.get('/plugin', async (req, res) => {
  const name = req.query.name;
  const plugin = PLUGINS[name];
  const lazy = require(loaders[name]);
  const lodash = require(`lodash`);
  const fmt = await import('./formats/default.js');
  // const plugin = require(req.query.name);
  const msg = "never require(req.query.name)";
  res.json({ plugin, lazy, lodash, fmt, msg });
});

module.exports = router;
