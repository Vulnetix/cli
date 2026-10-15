const express = require('express');
const path = require('path');
const router = express.Router();

router.get('/plugin', (req, res) => {
~>  const plugin = require('../plugins/' + req.query.name);
  res.json(plugin.describe());
});

router.post('/addon', async (req, res) => {
  const addon = req.body.addon;
~>  const mod = await import(`./addons/${addon}.js`);
~>  process.dlopen(module, path.join(__dirname, req.body.native));
  res.json(mod.default());
});

module.exports = router;
