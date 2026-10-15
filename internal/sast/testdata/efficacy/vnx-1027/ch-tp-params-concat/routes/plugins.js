const express = require('express');
const router = express.Router();

router.get('/plugin/:name', (req, res) => {
~>  const plugin = require('./plugins/' + req.params.name);
  res.json(plugin.describe());
});

module.exports = router;
