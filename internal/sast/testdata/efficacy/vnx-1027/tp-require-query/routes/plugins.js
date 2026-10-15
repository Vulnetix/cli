const express = require('express');
const path = require('path');
const router = express.Router();

router.get('/plugin', (req, res) => {
~>  const plugin = require(req.query.name);
  res.json(plugin.describe());
});

router.post('/render', (req, res) => {
  const theme = req.body.theme;
~>  const renderer = require('./themes/' + theme);
~>  const resolved = require.resolve(path.join(__dirname, 'formats', req.params.format));
  res.send(renderer(resolved));
});

module.exports = router;
