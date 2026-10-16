const path = require('path');
const express = require('express');

const app = express();

app.get('/plugins/:name/run', (req, res) => {
~>  const plugin = require(path.join(__dirname, 'plugins', req.params.name));
  res.json(plugin.run());
});

app.post('/addons/activate', async (req, res) => {
  const addon = req.body.addon;
~>  const mod = await import(`./addons/${addon}.js`);
  await mod.activate();
  res.sendStatus(204);
});

app.post('/native/load', (req, res) => {
  const target = { exports: {} };
~>  process.dlopen(target, req.query.lib);
  res.sendStatus(204);
});

module.exports = app;
